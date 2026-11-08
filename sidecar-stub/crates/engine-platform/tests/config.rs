use lemonvpn_engine_platform::{Ipv4Route, Platform, PortablePlatform, TunConfig};
use std::net::Ipv4Addr;

#[test]
fn rejects_inconsistent_stack_addresses_and_invalid_route_prefixes() {
    let mut config = TunConfig::default();
    assert!(config.validate().is_ok());
    config.host_address = config.stack_address;
    assert!(config.validate().is_err());
    config.host_address = Ipv4Addr::new(192, 0, 2, 1);
    assert!(config.validate().is_err());
    config = TunConfig::default();
    config.prefix_len = 33;
    assert!(config.validate().is_err());
    config = TunConfig::default();
    config.routes = vec![Ipv4Route {
        network: Ipv4Addr::UNSPECIFIED,
        prefix_len: 33,
    }];
    assert!(config.validate().is_err());
}

#[test]
fn portable_backend_reports_missing_tun_instead_of_a_false_success() {
    assert!(!PortablePlatform.tun_supported());
    assert!(matches!(PortablePlatform.open_tun(&TunConfig::default()),
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported));
}
