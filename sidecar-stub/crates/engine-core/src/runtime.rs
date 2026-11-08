//! Embeddable listener lifecycle. OS-specific startup and exit codes stay in
//! the executable; this module returns errors and supports explicit shutdown.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{config, events, http, logs, providers, proxy, socks5, state, tun};

#[derive(Clone, Debug)]
pub struct EngineOptions {
    /// Zero asks the OS to choose a free port. The API is always loopback-only.
    pub port: u16,
    /// None preserves the existing LEMONVPN_DATA_DIR / platform default lookup.
    pub data_dir: Option<PathBuf>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            port: 18080,
            data_dir: None,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct Shutdown(Arc<(Mutex<bool>, Condvar)>);

impl Shutdown {
    pub(crate) fn wait(&self, duration: Duration) -> bool {
        let (lock, wake) = &*self.0;
        let stopped = lock.lock().unwrap();
        *wake
            .wait_timeout_while(stopped, duration, |stopped| !*stopped)
            .unwrap()
            .0
    }

    fn cancel(&self) {
        let (lock, wake) = &*self.0;
        *lock.lock().unwrap() = true;
        wake.notify_all();
    }
}

static RUNNING: AtomicBool = AtomicBool::new(false);
static STOPPING: AtomicBool = AtomicBool::new(false);

pub(crate) fn stopping() -> bool {
    STOPPING.load(Ordering::SeqCst)
}

pub struct Engine {
    address: SocketAddr,
    shutdown: Shutdown,
    tasks: Vec<JoinHandle<()>>,
}

impl Engine {
    pub fn start(options: EngineOptions) -> io::Result<Self> {
        // Bind first so port-in-use retains its specific error and startup
        // cannot silently take over an existing listener.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, options.port))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        if RUNNING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "引擎已启动"));
        }
        if let Err(err) = config::set_data_dir(options.data_dir) {
            RUNNING.store(false, Ordering::SeqCst);
            return Err(err);
        }
        state::started();
        config::start();
        STOPPING.store(false, Ordering::SeqCst);
        crate::compat::set_router_port(address.port());
        let shutdown = Shutdown::default();
        let mut tasks = vec![
            providers::start(shutdown.clone()),
            state::start_recorder(shutdown.clone()),
            events::start(shutdown.clone()),
            crate::group_policy::start(shutdown.clone()),
            thread::spawn({
                let shutdown = shutdown.clone();
                move || {
                    while !shutdown.wait(Duration::from_secs(2)) {
                        config::refresh();
                        crate::compat::refresh_tun_processes();
                    }
                }
            }),
            thread::spawn({
                let shutdown = shutdown.clone();
                move || serve(listener, shutdown)
            }),
        ];
        if crate::compat::available() {
            match crate::dns::start_forwarder(shutdown.clone()) {
                Ok((port, task)) => {
                    crate::compat::set_dns_port(port);
                    tasks.push(task);
                }
                Err(error) => logs::warn(
                    "engine::dns",
                    "TUN DNS bridge could not start.",
                    Some(logs::fields(&[("error", &error.to_string())])),
                ),
            }
        }
        logs::info(
            "engine::listener",
            "Engine listener bound on loopback.",
            Some(logs::fields(&[("address", &address.to_string())])),
        );
        Ok(Self {
            address,
            shutdown,
            tasks,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn set_tun(&self, enabled: bool) -> io::Result<()> {
        if self.tasks.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "引擎已停止"));
        }
        if enabled {
            tun::enable()
        } else {
            tun::disable()
        }
    }

    pub fn tun_status_json(&self) -> String {
        tun::status_json()
    }

    /// Host-side TUN setup; the desktop HTTP switch uses the default settings.
    pub fn enable_tun(&self, config: crate::platform::TunConfig) -> io::Result<()> {
        if self.tasks.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "引擎已停止"));
        }
        tun::enable_with_config(config)
    }

    /// Stops packet capture, releases routes, closes clients and joins the
    /// listener and background producers. Safe to call more than once.
    pub fn shutdown(&mut self) -> io::Result<()> {
        if self.tasks.is_empty() {
            return Ok(());
        }
        STOPPING.store(true, Ordering::SeqCst);
        self.shutdown.cancel();
        crate::connections::close_all();
        let result = tun::disable();
        crate::compat::shutdown();
        for task in self.tasks.drain(..) {
            let _ = task.join();
        }
        RUNNING.store(false, Ordering::SeqCst);
        result
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn serve(listener: TcpListener, shutdown: Shutdown) {
    let mut clients: Vec<(TcpStream, JoinHandle<()>)> = Vec::new();
    loop {
        if shutdown.wait(Duration::ZERO) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // Windows accepted sockets inherit FIONBIO from the listener.
                // Protocol handlers use blocking IO on every platform.
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let Ok(socket) = stream.try_clone() else {
                    continue;
                };
                let task = thread::spawn(move || {
                    if let Err(err) = dispatch(stream) {
                        if !matches!(
                            err.kind(),
                            io::ErrorKind::BrokenPipe
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::UnexpectedEof
                        ) {
                            logs::warn(
                                "engine::inbound",
                                "Connection handling failed.",
                                Some(logs::fields(&[("kind", &format!("{:?}", err.kind()))])),
                            );
                        }
                    }
                });
                clients.push((socket, task));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if shutdown.wait(Duration::from_millis(10)) {
                    break;
                }
            }
            Err(err) => {
                logs::error(
                    "engine::listener",
                    "Listener accept failed.",
                    Some(logs::fields(&[("kind", &format!("{:?}", err.kind()))])),
                );
                if shutdown.wait(Duration::from_millis(100)) {
                    break;
                }
            }
        }
        let mut i = 0;
        while i < clients.len() {
            if clients[i].1.is_finished() {
                let (_, task) = clients.swap_remove(i);
                let _ = task.join();
            } else {
                i += 1;
            }
        }
    }
    drop(listener);
    for (socket, _) in &clients {
        let _ = socket.shutdown(std::net::Shutdown::Both);
    }
    for (_, task) in clients {
        let _ = task.join();
    }
}

fn dispatch(mut stream: TcpStream) -> io::Result<()> {
    if stopping() {
        return Ok(());
    }
    proxy::configure(&stream)?;
    match proxy::peek_protocol(&mut stream) {
        Ok(None) => Ok(()),
        Ok(Some(first)) if first == socks5::VERSION => {
            logs::debug(
                "engine::inbound",
                "Inbound connection accepted.",
                Some(logs::fields(&[("protocol", "socks5")])),
            );
            socks5::handle(stream)
        }
        Ok(Some(_)) => http::handle(stream),
        Err(err) => Err(err),
    }
}
