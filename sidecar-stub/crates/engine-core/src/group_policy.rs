//! Stateful group policies. Reading the API never advances a routing cursor.
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::{self, Group, Node, Policy};
use crate::runtime::Shutdown;
use ring::rand::{SecureRandom, SystemRandom};

const CHECK_INTERVAL: Duration = Duration::from_secs(60);
const HEALTH_TTL: Duration = Duration::from_secs(180);
const FAILURE_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Health {
    checks: VecDeque<(bool, Option<f64>)>,
    dials: VecDeque<bool>,
    moving: Option<f64>,
    dial_delay: Option<f64>,
    last_check: Option<(Instant, bool)>,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

#[derive(Clone, Copy)]
struct Quality {
    available: bool,
    moving: f64,
    average: f64,
    latest: f64,
    score: f64,
}

impl Health {
    fn quality(&self, now: Instant, network: &str) -> Quality {
        let failed_check = self.last_check.is_some_and(|(at, good)| {
            !good
                && now.duration_since(at) < HEALTH_TTL
                && self.last_success.is_none_or(|ok| ok < at)
        });
        let failed_dial = self.last_failure.is_some_and(|at| {
            now.duration_since(at) < FAILURE_COOLDOWN && self.last_success.is_none_or(|ok| ok < at)
        });
        let samples: Vec<f64> = self
            .checks
            .iter()
            .filter_map(|(ok, delay)| ok.then_some(*delay).flatten())
            .collect();
        let average = if samples.is_empty() {
            None
        } else {
            Some(samples.iter().sum::<f64>() / samples.len() as f64)
        };
        let jitter = average.map_or(0.0, |avg| {
            samples
                .iter()
                .map(|sample| (sample - avg).abs())
                .sum::<f64>()
                / samples.len() as f64
        });
        let total = self.checks.len() + self.dials.len();
        let good = self.checks.iter().filter(|(ok, _)| *ok).count()
            + self.dials.iter().filter(|ok| **ok).count();
        let reliability = (good + 1) as f64 / (total + 2) as f64;
        let delay = self.moving.or(self.dial_delay).unwrap_or(1000.0);
        // A DNS-only UDP benchmark failure can belong to the resolver, rather than the entire tunnel.
        // Penalize its ranking while keeping a usable relay available for actual UDP traffic.
        let penalty = if network == "udp" && failed_check {
            5000.0
        } else {
            0.0
        };
        Quality {
            available: (!failed_check || network == "udp") && !failed_dial,
            moving: self.moving.or(self.dial_delay).unwrap_or(1e12) + penalty,
            average: average.or(self.dial_delay).unwrap_or(1e12) + penalty,
            latest: samples.last().copied().or(self.dial_delay).unwrap_or(1e12) + penalty,
            score: delay / reliability.powi(2) + jitter + if total == 0 { 2000.0 } else { 0.0 },
        }
    }
}

#[derive(Default)]
struct Cursor {
    signature: String,
    next: usize,
    last: Option<String>,
}

#[derive(Default)]
struct State {
    health: HashMap<String, Health>,
    cursors: HashMap<(String, String), Cursor>,
    checks: HashMap<String, Instant>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
fn state() -> MutexGuard<'static, State> {
    STATE
        .get_or_init(|| Mutex::new(State::default()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

// Include the endpoint and credentials so replacing a node never inherits another node's health.
fn identity(node: &Node) -> String {
    crate::sha256::hex(
        format!(
            "{:?}",
            (
                &node.name,
                &node.protocol,
                &node.host,
                node.port,
                &node.username,
                &node.password,
                &node.link
            )
        )
        .as_bytes(),
    )
}
fn key(node: &Node, network: &str) -> String {
    format!("{}/{network}", identity(node))
}

pub(crate) fn probe_result(node: &Node, network: &str, good: bool, delay: Option<u32>) {
    config::sync_chain_selections();
    let mut state = state();
    let health = state.health.entry(key(node, network)).or_default();
    let delay = delay.map(|delay| delay as f64);
    health.last_check = Some((Instant::now(), good));
    health.checks.push_back((good, delay));
    while health.checks.len() > 10 {
        health.checks.pop_front();
    }
    if good {
        if let Some(delay) = delay {
            health.moving = Some(
                health
                    .moving
                    .map_or(delay, |previous| previous * 0.7 + delay * 0.3),
            );
        }
    }
    drop(state);
    config::sync_chain_selections();
}

pub(crate) fn dial_result(node: &Node, network: &str, good: bool, delay: Duration) {
    config::sync_chain_selections();
    let mut state = state();
    let health = state.health.entry(key(node, network)).or_default();
    let now = Instant::now();
    health.dials.push_back(good);
    while health.dials.len() > 32 {
        health.dials.pop_front();
    }
    if good {
        health.last_success = Some(now);
        let delay = delay.as_secs_f64() * 1000.0;
        health.dial_delay = Some(
            health
                .dial_delay
                .map_or(delay, |previous| previous * 0.7 + delay * 0.3),
        );
    } else {
        health.last_failure = Some(now);
    }
    drop(state);
    config::sync_chain_selections();
}

pub(crate) fn select(
    group: &Group,
    nodes: &[Node],
    network: &str,
    advance: bool,
) -> Option<String> {
    let mut state = state();
    let now = Instant::now();
    let candidates: Vec<(&Node, Quality)> = group
        .members
        .iter()
        .filter_map(|name| {
            let node = nodes.iter().find(|node| &node.name == name)?;
            let health = state.health.get(&key(node, network));
            let quality = health.map_or_else(
                || Health::default().quality(now, network),
                |health| health.quality(now, network),
            );
            quality.available.then_some((node, quality))
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let cursor = state
        .cursors
        .entry((group.name.clone(), network.to_owned()))
        .or_default();
    let signature = format!("{:?}:{:?}", group.policy, group.members);
    if cursor.signature != signature {
        *cursor = Cursor {
            signature,
            ..Cursor::default()
        };
    }
    let held = || {
        cursor
            .last
            .as_ref()
            .and_then(|last| candidates.iter().position(|(node, _)| &node.name == last))
    };
    let index = match group.policy {
        Policy::Fallback => held().unwrap_or(0),
        Policy::RoundRobin => {
            if !advance {
                held().unwrap_or(cursor.next % candidates.len())
            } else {
                cursor.next % candidates.len()
            }
        }
        Policy::Random => {
            if !advance {
                held().unwrap_or(0)
            } else {
                let mut bytes = [0u8; 8];
                if SystemRandom::new().fill(&mut bytes).is_ok() {
                    (u64::from_le_bytes(bytes) % candidates.len() as u64) as usize
                } else {
                    cursor.next % candidates.len()
                }
            }
        }
        policy => candidates
            .iter()
            .enumerate()
            .min_by(|(_, (_, left)), (_, (_, right))| {
                let cost = |quality: &Quality| match policy {
                    Policy::Average10 => quality.average,
                    Policy::LastDelay => quality.latest,
                    Policy::Score => quality.score,
                    _ => quality.moving,
                };
                cost(left).total_cmp(&cost(right))
            })
            .map(|(index, _)| index)?,
    };
    let name = candidates[index].0.name.clone();
    if advance {
        cursor.next = (index + 1) % candidates.len();
        cursor.last = Some(name.clone());
    }
    Some(name)
}

/// Checks run only for automatic groups, with two requests at most in flight.
/// This is part of the installed engine's lifecycle; building never starts it.
pub(crate) fn start(shutdown: Shutdown) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if shutdown.wait(Duration::from_secs(1)) {
                break;
            }
            config::refresh();
            config::sync_chain_selections();
            let (nodes, all_nodes, groups) = config::with_current(|config| {
                let wanted: HashSet<&str> = config
                    .groups
                    .iter()
                    .filter(|group| group.policy.automatic())
                    .flat_map(|group| group.members.iter().map(String::as_str))
                    .collect();
                (
                    config
                        .nodes
                        .iter()
                        .filter(|node| wanted.contains(node.name.as_str()))
                        .cloned()
                        .collect::<Vec<_>>(),
                    config.nodes.iter().map(identity).collect::<HashSet<_>>(),
                    config
                        .groups
                        .iter()
                        .map(|group| group.name.clone())
                        .collect::<HashSet<_>>(),
                )
            });
            let jobs = {
                let mut state = state();
                state.health.retain(|key, _| {
                    key.split_once('/')
                        .is_some_and(|(id, _)| all_nodes.contains(id))
                });
                state.cursors.retain(|(name, _), _| groups.contains(name));
                let wanted: HashSet<String> = nodes.iter().map(identity).collect();
                state.checks.retain(|key, _| wanted.contains(key));
                let now = Instant::now();
                let mut pending: Vec<_> = nodes
                    .into_iter()
                    .filter_map(|node| {
                        let key = identity(&node);
                        let last = state.checks.get(&key).copied();
                        if last.is_some_and(|at| now.duration_since(at) < CHECK_INTERVAL) {
                            return None;
                        }
                        Some((last, key, node))
                    })
                    .collect();
                // Unchecked nodes go first, then the oldest check, so large groups cannot starve.
                pending.sort_by_key(|(last, _, _)| *last);
                pending
                    .into_iter()
                    .take(2)
                    .map(|(_, key, node)| {
                        state.checks.insert(key, now);
                        node
                    })
                    .collect::<Vec<_>>()
            };
            let tasks: Vec<_> = jobs
                .into_iter()
                .map(|node| thread::spawn(move || crate::probes::check_policy_node(&node)))
                .collect();
            for task in tasks {
                let _ = task.join();
            }
            config::sync_chain_selections();
        }
    })
}
