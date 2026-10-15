use super::*;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn natted(ip: &str, net: &str) -> Local {
    Local {
        public: false,
        nets: vec![net.parse().unwrap()],
        public_ip: Some(ip.parse().unwrap()),
        have_relays: true,
    }
}

#[test]
fn the_path_follows_where_both_sides_are() {
    let natted_me = natted("203.0.113.1", "192.168.1.0/24");
    let cases = [
        (
            "the same NAT uses the LAN",
            natted_me.clone(),
            Remote {
                lan_endpoints: vec![sa("192.168.1.20:51820")],
                public_ip: Some("203.0.113.1".parse().unwrap()),
                ..Default::default()
            },
            Path::Lan(sa("192.168.1.20:51820")),
        ),
        (
            "the same subnet behind different NATs punches",
            natted_me.clone(),
            Remote {
                lan_endpoints: vec![sa("192.168.1.20:51820")],
                public_ip: Some("198.51.100.7".parse().unwrap()),
                ..Default::default()
            },
            Path::Punch,
        ),
        (
            "a public peer is dialled",
            natted_me.clone(),
            Remote {
                public_endpoints: vec![sa("[2001:db8::1]:51820"), sa("198.51.100.9:51820")],
                public_ip: Some("198.51.100.9".parse().unwrap()),
                ..Default::default()
            },
            Path::Public(sa("198.51.100.9:51820")),
        ),
        (
            "a public node waits for a NATed peer",
            Local {
                public: true,
                ..natted_me
            },
            Remote {
                public_ip: Some("192.0.2.4".parse().unwrap()),
                ..Default::default()
            },
            Path::Await,
        ),
        (
            "a LAN-only cluster without relays",
            Local {
                nets: vec!["10.0.0.0/24".parse().unwrap()],
                ..Default::default()
            },
            Remote {
                lan_endpoints: vec![sa("10.0.0.5:51820")],
                ..Default::default()
            },
            Path::Lan(sa("10.0.0.5:51820")),
        ),
    ];
    for (what, me, peer, expected) in cases {
        assert_eq!(plan(&me, &peer), expected, "{what}");
    }
}
