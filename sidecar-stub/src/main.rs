//! LemonVPN engine sidecar (POC).
//!
//! Serves the read-only slice of the native API doona's first screen reads and
//! hosts a mixed HTTP/SOCKS5 inbound on loopback: the first byte tells the two
//! apart, so a system proxy can point both protocols at one port.
//!
//! Egress is direct today. honk's dialer and rule engine plug in behind
//! [`proxy::dial`] later; the inbound side stays the same.

mod api;
mod base64;
mod config;
mod connections;
mod dns;
mod events;
mod fetch;
mod flows;
mod http;
mod json;
mod logs;
mod outbound;
mod outbounds;
mod probes;
mod providers;
mod proxy;
mod share;
mod sha256;
mod socks5;
mod state;

use std::env;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::process;
use std::thread;

const DEFAULT_PORT: u16 = 18080;
const PORT_ENV: &str = "LEMONVPN_ENGINE_PORT";
/// Loopback only. The listener has no authentication, so binding it to a
/// routable address would turn the machine into an open proxy.
const BIND_ADDR: &str = "127.0.0.1";

/// Exit code the shell reads as "the port is taken". It must not be mistaken
/// for a crash, and the shell must never adopt a stranger's listener.
const EXIT_PORT_IN_USE: i32 = 3;

fn main() {
    // Uptime counts from here, not from the first API read.
    state::started();
    config::start();
    providers::start();
    let port = port_from_env();

    let listener = match TcpListener::bind((BIND_ADDR, port)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("lemonvpn-engine-stub: failed to bind {BIND_ADDR}:{port}: {err}");
            process::exit(EXIT_PORT_IN_USE);
        }
    };

    let local_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| format!("{BIND_ADDR}:{port}"));
    logs::info(
        "engine::listener",
        "Engine listener bound on loopback.",
        Some(logs::fields(&[("address", local_addr.as_str())])),
    );
    eprintln!("lemonvpn-engine-stub listening on http://{local_addr}");
    state::start_recorder();
    events::start();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(err) = dispatch(stream) {
                        // A client that gives up mid-request is normal for a
                        // polling UI, not a fault worth a line each time.
                        if !matches!(
                            err.kind(),
                            ErrorKind::BrokenPipe
                                | ErrorKind::ConnectionReset
                                | ErrorKind::ConnectionAborted
                                | ErrorKind::UnexpectedEof
                        ) {
                            let kind = format!("{:?}", err.kind());
                            logs::warn(
                                "engine::inbound",
                                "Connection handling failed.",
                                Some(logs::fields(&[("kind", &kind)])),
                            );
                            eprintln!("lemonvpn-engine-stub: connection error: {err}");
                        }
                    }
                });
            }
            Err(err) => {
                let kind = format!("{:?}", err.kind());
                logs::error(
                    "engine::listener",
                    "Listener accept failed.",
                    Some(logs::fields(&[("kind", &kind)])),
                );
                eprintln!("lemonvpn-engine-stub: accept error: {err}");
            }
        }
    }
}

fn dispatch(stream: TcpStream) -> std::io::Result<()> {
    proxy::configure(&stream)?;

    let mut first = [0u8; 1];
    match stream.peek(&mut first) {
        Ok(0) => Ok(()),
        Ok(_) if first[0] == socks5::VERSION => {
            logs::debug(
                "engine::inbound",
                "Inbound connection accepted.",
                Some(logs::fields(&[("protocol", "socks5")])),
            );
            socks5::handle(stream)
        }
        Ok(_) => http::handle(stream),
        Err(err) => Err(err),
    }
}

fn port_from_env() -> u16 {
    match env::var(PORT_ENV) {
        Ok(value) => match value.trim().parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("lemonvpn-engine-stub: invalid {PORT_ENV}={value:?}, using {DEFAULT_PORT}");
                DEFAULT_PORT
            }
        },
        Err(_) => DEFAULT_PORT,
    }
}
