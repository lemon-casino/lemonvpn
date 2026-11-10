//! An opt-in proxy-only listener. The control API stays on loopback.
use crate::{config, http, logs, proxy, socks5};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs, io,
    net::{Ipv4Addr, Shutdown, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    pub username: String,
    pub password: String,
}
impl Credentials {
    pub(crate) fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        // Both credentials must be checked, without early return on a mismatch.
        fn equal(left: &[u8], right: &[u8]) -> bool {
            let mut mismatch = left.len() ^ right.len();
            for index in 0..left.len().max(right.len()) {
                mismatch |= usize::from(
                    left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
                );
            }
            mismatch == 0
        }
        equal(self.username.as_bytes(), username) & equal(self.password.as_bytes(), password)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Settings {
    enabled: bool,
    bind_address: Ipv4Addr,
    port: u16,
    authentication: Option<Credentials>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: Ipv4Addr::UNSPECIFIED,
            port: 18081,
            authentication: None,
        }
    }
}
impl Settings {
    fn validate(&self) -> io::Result<()> {
        if self.port < 1024
            || (!self.bind_address.is_unspecified() && !self.bind_address.is_private())
        {
            return Err(io::Error::other(
                "请选择局域网 IPv4 地址（或 0.0.0.0），端口须为 1024～65535",
            ));
        }
        if let Some(auth) = &self.authentication {
            let valid = |value: &str| {
                !value.is_empty()
                    && value.len() <= 128
                    && value.bytes().all(|b| (33..=126).contains(&b))
            };
            if !valid(&auth.username) || auth.username.contains(':') || !valid(&auth.password) {
                return Err(io::Error::other(
                    "用户名和密码须为 1～128 位可见英文字符，用户名不能含冒号",
                ));
            }
        }
        Ok(())
    }
}
struct Listener {
    socket: TcpListener,
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}
impl Listener {
    fn open(settings: &Settings, previous: Option<&Self>) -> io::Result<TcpListener> {
        let same = previous.filter(|previous| {
            previous.socket.local_addr().is_ok_and(|address| {
                address.ip() == settings.bind_address && address.port() == settings.port
            })
        });
        let socket = match same {
            Some(previous) => previous.socket.try_clone()?,
            None => TcpListener::bind((settings.bind_address, settings.port))?,
        };
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
    fn start(socket: TcpListener, settings: Settings) -> io::Result<Self> {
        let acceptor = socket.try_clone()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let ready = Arc::new(AtomicBool::new(false));
        let active = ready.clone();
        // Spawn before committing settings so a thread-creation failure cannot
        // leave a saved enabled flag with no serving thread.
        let task = thread::Builder::new()
            .name("lan-proxy".into())
            .spawn(move || {
                while !active.load(Ordering::SeqCst) {
                    if stopped.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                serve(acceptor, settings, stopped);
            })?;
        Ok(Self {
            socket,
            stop,
            ready,
            task: Some(task),
        })
    }
    fn activate(&self) {
        self.ready.store(true, Ordering::SeqCst);
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
#[derive(Default)]
struct State {
    settings: Option<Settings>,
    listener: Option<Listener>,
    error: Option<String>,
}
static STATE: Mutex<State> = Mutex::new(State {
    settings: None,
    listener: None,
    error: None,
});
fn read(state: &mut State) -> io::Result<Settings> {
    if let Some(settings) = &state.settings {
        return Ok(settings.clone());
    }
    let settings = match fs::read(config::data_dir().join("lan-settings.json")) {
        Ok(bytes) if bytes.len() <= 8192 => {
            serde_json::from_slice::<Settings>(&bytes).map_err(io::Error::other)?
        }
        Ok(_) => return Err(io::Error::other("局域网设置文件过大")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Settings::default(),
        Err(error) => return Err(error),
    };
    settings.validate()?;
    state.settings = Some(settings.clone());
    Ok(settings)
}
fn revision(settings: &Settings) -> String {
    crate::sha256::hex(&serde_json::to_vec(settings).unwrap())
}
fn status(state: &mut State) -> io::Result<String> {
    let settings = read(state)?;
    let (addresses, address_error) = match crate::platform::lan::addresses() {
        Ok(addresses) => (addresses, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    Ok(json!({"settings": settings, "revision": revision(&settings), "active": state.listener.is_some(), "error": state.error, "addresses": addresses, "address_error": address_error, "protocols": ["http", "socks5"], "ipv4_only": true}).to_string())
}
pub(crate) fn status_json() -> io::Result<String> {
    status(&mut STATE.lock().unwrap_or_else(|p| p.into_inner()))
}
pub(crate) fn start() {
    let mut state = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let result = (|| {
        let settings = read(&mut state)?;
        if settings.enabled {
            state.listener = Some(Listener::start(Listener::open(&settings, None)?, settings)?);
        }
        if let Some(listener) = &state.listener {
            listener.activate();
        }
        state.error = None;
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = result {
        logs::warn(
            "engine::lan",
            "LAN proxy listener could not start.",
            Some(logs::fields(&[("error", &error.to_string())])),
        );
        state.error = Some(error.to_string());
    }
}
pub(crate) fn shutdown() {
    STATE.lock().unwrap_or_else(|p| p.into_inner()).listener = None;
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    revision: String,
    settings: Settings,
}
pub(crate) fn update(body: &str) -> Result<String, (u16, &'static str, String)> {
    let invalid = |error: String| (422, "invalid_lan_settings", error);
    if body.len() > 8192 {
        return Err((413, "request_too_large", "局域网设置过大".into()));
    }
    let update: Update = serde_json::from_str(body).map_err(|e| invalid(e.to_string()))?;
    update
        .settings
        .validate()
        .map_err(|e| invalid(e.to_string()))?;
    let mut state = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let old = read(&mut state).map_err(|e| (500, "lan_settings_read_failed", e.to_string()))?;
    if update.revision != revision(&old) {
        return Err((409, "conflict", "局域网设置已变更，请重新加载后保存".into()));
    }
    let next = update.settings;
    if next != old || (next.enabled && state.listener.is_none()) {
        let listener = if next.enabled {
            Some(
                Listener::start(
                    Listener::open(&next, state.listener.as_ref()).map_err(|e| {
                        (
                            409,
                            "lan_bind_failed",
                            format!("共享端口无法监听，原设置未变更：{e}"),
                        )
                    })?,
                    next.clone(),
                )
                .map_err(|e| (503, "lan_start_failed", e.to_string()))?,
            )
        } else {
            None
        };
        // Reserving a replacement listener does not touch the API or local
        // proxy; a failed persistence operation drops only the replacement.
        crate::storage::write_atomic(
            &config::data_dir().join("lan-settings.json"),
            &serde_json::to_vec_pretty(&next).unwrap(),
        )
        .map_err(|e| (500, "lan_settings_write_failed", e.to_string()))?;
        state.listener = listener;
        if let Some(listener) = &state.listener {
            listener.activate();
        }
        state.settings = Some(next);
        state.error = None;
        crate::events::emit(
            "runtime.updated",
            json!({"reason": "lan_settings"}).to_string(),
        );
    }
    status(&mut state).map_err(|e| (500, "lan_settings_read_failed", e.to_string()))
}
fn serve(listener: TcpListener, settings: Settings, stop: Arc<AtomicBool>) {
    let mut clients: Vec<(TcpStream, JoinHandle<()>)> = Vec::new();
    while !stop.load(Ordering::SeqCst) && !crate::runtime::stopping() {
        match listener.accept() {
            Ok((stream, peer)) => {
                // Binding all interfaces never permits Internet-facing peers.
                // Keep the TUN broker's privileged SOCKS credentials out of LAN.
                if !matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_private() || ip.is_loopback())
                    || clients.len() >= 256
                {
                    continue;
                }
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let Ok(socket) = stream.try_clone() else {
                    continue;
                };
                let auth = settings.authentication.clone();
                let client_stop = stop.clone();
                let Ok(task) = thread::Builder::new()
                    .name("lan-client".into())
                    .spawn(move || {
                        let _ = (|| {
                            proxy::configure(&stream)?;
                            let mut stream = stream;
                            match proxy::peek_protocol(&mut stream)? {
                                None => Ok(()),
                                Some(socks5::VERSION) => {
                                    socks5::handle_lan(stream, auth.as_ref(), &client_stop)
                                }
                                Some(_) => http::handle_lan(stream, auth.as_ref(), &client_stop),
                            }
                        })() as io::Result<()>;
                    })
                else {
                    continue;
                };
                clients.push((socket, task));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
        clients.retain_mut(|(_, task)| !task.is_finished());
    }
    for (socket, _) in &clients {
        crate::connections::close_inbound(socket);
        let _ = socket.shutdown(Shutdown::Both);
    }
    // Workers may still be completing an outbound dial. Do not block the
    // settings API on a remote connect timeout; closing sockets cancels relay.
}
