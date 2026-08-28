mod config_api;
mod context;
mod cors;
mod observability;
mod proxy;
mod response;
mod routes;
mod server;
mod tls;

pub use context::{ConfigUpdate, ConfigUpdateKind};
pub use proxy::{healthcheck_proxy_group, healthcheck_proxy_provider_config};
#[cfg(unix)]
pub use server::serve_unix;
#[cfg(windows)]
pub use server::{prepare_named_pipe, serve_named_pipe};
pub use server::{serve, serve_tcp, serve_tls};
pub use tls::prepare_tls_config;

#[cfg(test)]
mod tests {
    use crate::cors::wildcard_origin_matches;
    use crate::proxy::parse_status_ranges;
    use crate::response::dns_record_type;
    use crate::routes::is_doh_path;

    #[test]
    fn mirrors_go_dns_record_type_names() {
        assert_eq!(dns_record_type(""), Some(1));
        assert_eq!(dns_record_type("SOA"), Some(6));
        assert_eq!(dns_record_type("HTTPS"), Some(65));
        assert_eq!(dns_record_type("NSAP-PTR"), Some(23));
        assert_eq!(dns_record_type("Reserved"), Some(u16::MAX));
        assert_eq!(dns_record_type("soa"), None);
        assert_eq!(dns_record_type("TYPE65"), None);
    }

    #[test]
    fn external_doh_mount_has_segment_boundary() {
        assert!(is_doh_path("/dns-query", "/dns-query"));
        assert!(is_doh_path("/dns-query/child", "/dns-query"));
        assert!(!is_doh_path("/dns-query-other", "/dns-query"));
        assert!(!is_doh_path("/dns-query", "dns-query"));
    }

    #[test]
    fn mirrors_go_single_wildcard_origin_matching() {
        assert!(wildcard_origin_matches(
            "https://*.example.test",
            "https://app.example.test"
        ));
        assert!(!wildcard_origin_matches(
            "https://*.example.test",
            "http://app.example.test"
        ));
        assert!(wildcard_origin_matches(
            "https://exact.example.test",
            "https://exact.example.test"
        ));
        assert!(!wildcard_origin_matches(
            "https://exact.example.test",
            "https://other.example.test"
        ));
    }

    #[test]
    fn parses_controller_expected_status_ranges() {
        assert_eq!(parse_status_ranges(""), Some(Vec::new()));
        assert_eq!(parse_status_ranges("*"), Some(Vec::new()));
        assert_eq!(
            parse_status_ranges("200/204,301-303"),
            Some(vec![(200, 200), (204, 204), (301, 303)])
        );
        assert_eq!(parse_status_ranges("invalid"), None);
        assert_eq!(parse_status_ranges("303-301"), None);
    }
}
