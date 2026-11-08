//! Native recovery fixture: one reserved /32 route, a unique adapter/address,
//! and a real physical-interface-bound mixed outbound. Never changes defaults.
#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use lemonvpn_engine_core::platform::{parent::ParentProcess, Ipv4Route, TunConfig};
    use lemonvpn_engine_core::{Engine, EngineOptions};
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    let args: Vec<_> = std::env::args().collect();
    let directory = PathBuf::from(args.get(1).expect("isolated data directory"));
    let parent = ParentProcess::open(args.get(2).expect("owner PID").parse().expect("numeric PID"))?;
    std::fs::create_dir_all(&directory)?;
    let echo = TcpListener::bind("127.0.0.1:0")?;
    let node = echo.local_addr()?;
    std::thread::spawn(move || {
        for stream in echo.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || -> std::io::Result<()> {
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut greeting = [0; 3]; stream.read_exact(&mut greeting)?;
                if greeting != [5, 1, 0] { return Ok(()) }
                stream.write_all(&[5, 0])?;
                let mut request = [0; 10]; stream.read_exact(&mut request)?;
                if request[..4] != [5, 1, 0, 1] { return Ok(()) }
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
                stream.set_read_timeout(None)?;
                let mut writer = stream.try_clone()?;
                let _ = std::io::copy(&mut stream, &mut writer);
                Ok(())
            });
        }
    });
    let target = Ipv4Addr::new(203, 0, 113, 198);
    std::fs::write(directory.join("config.dae"), format!(
        "node {{\n echo: 'socks5://{node}'\n}}\nrouting {{\n ip(cidr: {target}/32) -> echo\n fallback: direct\n}}\n"
    ))?;
    let mut engine = Engine::start(EngineOptions { port: 0, data_dir: Some(directory.clone()) })?;
    let adapter = format!("LemonVPN-Recovery-{}", std::process::id());
    engine.enable_tun(TunConfig {
        name: adapter.clone(),
        stack_address: Ipv4Addr::new(10, 212, 0, 1),
        host_address: Ipv4Addr::new(10, 212, 0, 2),
        routes: vec![Ipv4Route { network: target, prefix_len: 32 }],
        ..TunConfig::default()
    })?;
    let ready = format!("{{\"pid\":{},\"port\":{},\"target\":\"{target}\",\"adapter\":\"{adapter}\"}}", std::process::id(), engine.local_addr().port());
    std::fs::write(directory.join("ready.json"), &ready)?;
    println!("{ready}");
    let deadline = Instant::now() + Duration::from_secs(7200);
    while parent.running() && Instant::now() < deadline && !directory.join("stop").exists() {
        std::thread::sleep(Duration::from_millis(250));
    }
    engine.shutdown()?;
    println!("TUN recovery fixture stopped and released its reserved route");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This opt-in fixture requires Windows, administrator rights and Wintun");
}
