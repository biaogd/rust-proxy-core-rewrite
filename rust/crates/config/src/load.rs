use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ipnet::IpNet;
use rewrite_model::AuthUser;
use rewrite_rules::{ProviderDefinition, RematchSpec, RuleSet};

use crate::dns::{
    extend_geodata_rule_providers, load_rule_provider_file, parse_dns, parse_hosts,
    parse_rule_provider_domain, parse_rule_provider_source, parse_rule_providers,
};
use crate::error::ConfigError;
use crate::model::{
    Config, ConfigSpec, ControllerCors, ControllerTls, GeoXUrls, ListenerKind, LogLevel, Mode,
    NormalizedConfig, NtpConfig, ProfileConfig, ProxyConfig, ProxyGroupKind, RuleProviderVehicle,
    ShadowsocksInboundConfig,
};
use crate::named_listeners::{parse_shadowsocks_listeners, validate_shadowsocks_listener_ports};
use crate::proxy::{
    expand_proxy_group, load_proxy_provider_file, parse_proxies, parse_proxy_groups,
    parse_proxy_provider_source, parse_proxy_providers, proxy_member_types,
};
use crate::raw::{RawConfig, RawControllerCors, RawGeoXUrls, RawNtp, RawProfile, RawTls};

impl ConfigSpec {
    /// Parses the Phase 2 specification layer and overlays Go-compatible
    /// defaults for the declared general fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for malformed YAML, invalid enums, unsupported
    /// proxy specifications or invalid pure rules.
    pub fn from_yaml(source: &str) -> Result<Self, ConfigError> {
        Self::from_source(source, None, None, false)
    }

    /// Parses YAML with the process-level geodata-mode default selected by
    /// the CLI. An explicit YAML value still takes precedence.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_with_geodata_mode(
        source: &str,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        Self::from_source(source, None, None, geodata_mode)
    }

    /// Parses YAML with provider paths rooted at the supplied home directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_with_provider_directory(
        source: &str,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        Self::from_source(source, None, Some(provider_directory), geodata_mode)
    }

    /// Parses YAML while resolving relative resources from a configuration path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_at_path_with_geodata_mode(
        source: &str,
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        let mut parsed = Self::from_source(source, path.parent(), path.parent(), geodata_mode)?;
        parsed.source_path = Some(path.to_path_buf());
        Ok(parsed)
    }

    /// Parses YAML with separate configuration-resource and provider-home directories.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_at_path_with_provider_directory(
        source: &str,
        path: &Path,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        let mut parsed = Self::from_source(
            source,
            path.parent(),
            Some(provider_directory),
            geodata_mode,
        )?;
        parsed.source_path = Some(path.to_path_buf());
        Ok(parsed)
    }

    #[allow(clippy::too_many_lines)]
    fn from_source(
        source: &str,
        config_directory: Option<&Path>,
        provider_directory: Option<&Path>,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        let raw = serde_yaml_ng::from_str::<Option<RawConfig>>(source)?.unwrap_or_default();
        let mode = parse_mode(raw.mode.as_deref().unwrap_or("rule"))?;
        let log_level = parse_log_level(raw.log_level.as_deref().unwrap_or("info"))?;
        let geodata_mode = raw.geodata_mode.unwrap_or(geodata_mode);
        let raw_rules = raw.rules.unwrap_or_default();
        let raw_sub_rules = raw.sub_rules.unwrap_or_default();
        let (rematches, proxies) =
            parse_proxies(raw.proxies.unwrap_or_default(), true, provider_directory)?;
        let proxy_providers = parse_proxy_providers(
            raw.proxy_providers.unwrap_or_default(),
            provider_directory,
            &proxies,
        )?;
        let proxy_groups = parse_proxy_groups(
            raw.proxy_groups.unwrap_or_default(),
            &proxies,
            &proxy_providers,
        )?;
        let rule_providers =
            parse_rule_providers(raw.rule_providers.unwrap_or_default(), provider_directory)?;
        let proxy_targets = proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .chain(proxy_groups.iter().map(|group| group.name.clone()))
            .collect();
        let mut provider_definitions: BTreeMap<String, ProviderDefinition> = rule_providers
            .iter()
            .map(|(name, provider)| {
                (
                    name.clone(),
                    ProviderDefinition {
                        behavior: provider.behavior,
                        payload: provider.payload.clone(),
                    },
                )
            })
            .collect();
        extend_geodata_rule_providers(
            &raw_rules,
            &raw_sub_rules,
            provider_directory.or(config_directory),
            geodata_mode,
            &mut provider_definitions,
        )?;
        let rules = RuleSet::parse_with_targets_and_providers(
            &raw_rules,
            &raw_sub_rules,
            &rematches,
            &proxy_targets,
            &provider_definitions,
        )?;
        let profile = parse_profile(raw.profile)?;
        let ntp = parse_ntp(raw.ntp)?;
        let geox_url = parse_geox_urls(raw.geox_url)?;
        let (controller_tls, trust_certificates) = parse_tls(raw.tls, provider_directory)?;
        let controller_cors = parse_controller_cors(raw.external_controller_cors);
        let dns = parse_dns(
            raw.dns,
            &trust_certificates,
            &rule_providers,
            provider_directory.or(config_directory),
            geodata_mode,
        )?;
        let external_ui = raw.external_ui.unwrap_or_default();
        let external_ui_name = raw.external_ui_name.unwrap_or_default();
        validate_external_ui(&external_ui, &external_ui_name, provider_directory)?;

        let skip_auth_prefixes = parse_inbound_prefixes(
            raw.skip_auth_prefixes.unwrap_or_default(),
            "skip-auth-prefixes",
        )?;
        let lan_allowed_ips = parse_inbound_prefixes(
            raw.lan_allowed_ips
                .unwrap_or_else(|| vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()]),
            "lan-allowed-ips",
        )?;
        let lan_disallowed_ips = parse_inbound_prefixes(
            raw.lan_disallowed_ips.unwrap_or_default(),
            "lan-disallowed-ips",
        )?;

        let allow_lan = raw.allow_lan.unwrap_or(false);
        let bind_address = raw.bind_address.clone().unwrap_or_else(|| "*".to_owned());
        let mut shadowsocks_listeners =
            parse_shadowsocks_listeners(raw.listeners.clone(), allow_lan, &bind_address)?;
        if let Some(config) = raw
            .ss_config
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| ShadowsocksInboundConfig::parse_ss_url(value, allow_lan, &bind_address))
            .transpose()?
        {
            shadowsocks_listeners.insert(0, config);
        }
        validate_shadowsocks_listener_ports(&shadowsocks_listeners)?;

        Ok(Self {
            port: raw.port.unwrap_or(0),
            socks_port: raw.socks_port.unwrap_or(0),
            redir_port: raw.redir_port.unwrap_or(0),
            tproxy_port: raw.tproxy_port.unwrap_or(0),
            mixed_port: raw.mixed_port.unwrap_or(0),
            allow_lan: raw.allow_lan.unwrap_or(false),
            bind_address: raw.bind_address.unwrap_or_else(|| "*".to_owned()),
            skip_auth_prefixes,
            lan_allowed_ips,
            lan_disallowed_ips,
            inbound_tfo: raw.inbound_tfo.unwrap_or(false),
            inbound_mptcp: raw.inbound_mptcp.unwrap_or(false),
            mode,
            unified_delay: raw.unified_delay.unwrap_or(false),
            log_level,
            ipv6: raw.ipv6.unwrap_or(true),
            geodata_mode,
            geodata_loader: raw
                .geodata_loader
                .unwrap_or_else(|| "memconservative".to_owned()),
            geosite_matcher: normalize_geosite_matcher(raw.geosite_matcher.as_deref()),
            geo_auto_update: raw.geo_auto_update.unwrap_or(false),
            geo_update_interval: raw.geo_update_interval.unwrap_or(24),
            geox_url,
            interface_name: raw.interface_name.unwrap_or_default(),
            routing_mark: raw.routing_mark.unwrap_or(0),
            tcp_concurrent: raw.tcp_concurrent.unwrap_or(false),
            keep_alive_idle: raw.keep_alive_idle.unwrap_or(0),
            keep_alive_interval: raw.keep_alive_interval.unwrap_or(0),
            disable_keep_alive: raw.disable_keep_alive.unwrap_or(false),
            etag_support: raw.etag_support.unwrap_or(true),
            authentication: parse_authentication(raw.authentication.unwrap_or_default()),
            external_controller: raw.external_controller.unwrap_or_default(),
            external_controller_tls: raw.external_controller_tls.unwrap_or_default(),
            external_controller_unix: raw.external_controller_unix.unwrap_or_default(),
            external_controller_pipe: raw.external_controller_pipe.unwrap_or_default(),
            external_controller_routing_mark: raw
                .external_controller_routing_mark
                .unwrap_or_default(),
            external_ui,
            external_ui_url: raw.external_ui_url.unwrap_or_else(|| {
                "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip".to_owned()
            }),
            external_ui_name,
            external_doh_server: raw.external_doh_server.unwrap_or_default(),
            secret: raw.secret.unwrap_or_default(),
            controller_cors,
            profile,
            ntp,
            trust_certificates,
            controller_tls,
            dns,
            hosts: parse_hosts(raw.hosts.unwrap_or_default())?,
            raw_rules,
            raw_sub_rules,
            rematches,
            proxies,
            proxy_providers,
            rule_providers,
            proxy_groups,
            rules,
            shadowsocks_listeners,
            unsupported_keys: raw.extra.into_keys().collect(),
            source_path: None,
            home_directory: provider_directory.map(Path::to_path_buf),
        })
    }

    /// Reads and parses a Phase 2 configuration specification.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file I/O or specification errors.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let mut parsed = Self::from_source(
            &std::fs::read_to_string(path)?,
            path.parent(),
            path.parent(),
            false,
        )?;
        parsed.source_path = Some(path.to_path_buf());
        Ok(parsed)
    }

    /// Reads YAML with the process-level geodata-mode default selected by the
    /// CLI. An explicit YAML value still takes precedence.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_path`].
    pub fn from_path_with_geodata_mode(
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        let mut parsed = Self::from_source(
            &std::fs::read_to_string(path)?,
            path.parent(),
            path.parent(),
            geodata_mode,
        )?;
        parsed.source_path = Some(path.to_path_buf());
        Ok(parsed)
    }

    /// Ensures no top-level feature outside the declared Phase 2 parser surface
    /// was silently ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::UnsupportedKey`] for the first unsupported key.
    pub fn validate_declared_surface(&self) -> Result<(), ConfigError> {
        if let Some(key) = self.unsupported_keys.first() {
            Err(ConfigError::UnsupportedKey(key.clone()))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn normalized(&self) -> NormalizedConfig {
        NormalizedConfig {
            port: self.port,
            socks_port: self.socks_port,
            redir_port: self.redir_port,
            tproxy_port: self.tproxy_port,
            mixed_port: self.mixed_port,
            allow_lan: self.allow_lan,
            bind_address: self.bind_address.clone(),
            mode: self.mode,
            unified_delay: self.unified_delay,
            log_level: self.log_level,
            ipv6: self.ipv6,
            interface_name: self.interface_name.clone(),
            routing_mark: self.routing_mark,
            tcp_concurrent: self.tcp_concurrent,
            keep_alive_idle: self.keep_alive_idle,
            keep_alive_interval: self.keep_alive_interval,
            disable_keep_alive: self.disable_keep_alive,
            etag_support: self.etag_support,
            rules: self.raw_rules.clone(),
            sub_rules: self.raw_sub_rules.clone(),
        }
    }
}

impl TryFrom<ConfigSpec> for Config {
    type Error = ConfigError;

    fn try_from(spec: ConfigSpec) -> Result<Self, Self::Error> {
        spec.validate_declared_surface()?;
        let proxy_targets = spec
            .proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .chain(spec.proxy_groups.iter().map(|group| group.name.clone()))
            .collect();
        let unsupported = [
            (spec.redir_port != 0, "redir-port"),
            (spec.tproxy_port != 0, "tproxy-port"),
            (spec.unified_delay, "unified-delay"),
            (
                !spec.rules.is_phase_three_tcp_with_targets(&proxy_targets),
                "rules outside Phase 3A TCP",
            ),
        ];
        if let Some((_, feature)) = unsupported.into_iter().find(|(active, _)| *active) {
            return Err(ConfigError::UnsupportedRuntime(feature.to_owned()));
        }

        Ok(Self {
            port: spec.port,
            socks_port: spec.socks_port,
            mixed_port: spec.mixed_port,
            allow_lan: spec.allow_lan,
            bind_address: spec.bind_address,
            skip_auth_prefixes: spec.skip_auth_prefixes,
            lan_allowed_ips: spec.lan_allowed_ips,
            lan_disallowed_ips: spec.lan_disallowed_ips,
            inbound_tfo: spec.inbound_tfo,
            inbound_mptcp: spec.inbound_mptcp,
            interface_name: spec.interface_name,
            routing_mark: spec.routing_mark,
            tcp_concurrent: spec.tcp_concurrent,
            keep_alive_idle: spec.keep_alive_idle,
            keep_alive_interval: spec.keep_alive_interval,
            disable_keep_alive: spec.disable_keep_alive,
            mode: spec.mode,
            log_level: spec.log_level,
            ipv6: spec.ipv6,
            geodata_mode: spec.geodata_mode,
            geodata_loader: spec.geodata_loader,
            geosite_matcher: spec.geosite_matcher,
            geo_auto_update: spec.geo_auto_update,
            geo_update_interval: spec.geo_update_interval,
            geox_url: spec.geox_url,
            etag_support: spec.etag_support,
            authentication: spec.authentication,
            external_controller: spec.external_controller,
            external_controller_tls: spec.external_controller_tls,
            external_controller_unix: spec.external_controller_unix,
            external_controller_pipe: spec.external_controller_pipe,
            external_controller_routing_mark: spec.external_controller_routing_mark,
            external_ui: spec.external_ui,
            external_ui_url: spec.external_ui_url,
            external_ui_name: spec.external_ui_name,
            external_doh_server: spec.external_doh_server,
            secret: spec.secret,
            controller_cors: spec.controller_cors,
            profile: spec.profile,
            ntp: spec.ntp,
            trust_certificates: spec.trust_certificates,
            controller_tls: spec.controller_tls,
            dns: spec.dns,
            hosts: spec.hosts,
            proxies: spec.proxies,
            proxy_providers: spec.proxy_providers,
            rule_providers: spec.rule_providers,
            proxy_groups: spec.proxy_groups,
            rules: spec.rules,
            raw_rules: spec.raw_rules,
            raw_sub_rules: spec.raw_sub_rules,
            rematches: spec.rematches,
            shadowsocks_listeners: spec.shadowsocks_listeners,
            source_path: spec.source_path,
            home_directory: spec.home_directory,
        })
    }
}

impl Config {
    /// Parses a configuration and converts it to the current executable
    /// runtime subset.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification errors or any setting that the
    /// narrow runtime cannot apply.
    pub fn from_yaml(source: &str) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml(source)?.try_into()
    }

    /// Parses runtime YAML using the CLI geodata-mode default.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_with_geodata_mode(
        source: &str,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_with_geodata_mode(source, geodata_mode)?.try_into()
    }

    /// Parses runtime YAML with provider paths rooted at the supplied home directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_with_provider_directory(
        source: &str,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_with_provider_directory(source, provider_directory, geodata_mode)?
            .try_into()
    }

    /// Parses runtime YAML while resolving relative resources from a path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_at_path_with_geodata_mode(
        source: &str,
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_at_path_with_geodata_mode(source, path, geodata_mode)?.try_into()
    }

    /// Parses runtime YAML with provider paths rooted at the CLI home directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_at_path_with_provider_directory(
        source: &str,
        path: &Path,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_at_path_with_provider_directory(
            source,
            path,
            provider_directory,
            geodata_mode,
        )?
        .try_into()
    }

    /// Reads, parses and converts a configuration for the current runtime.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file, specification or runtime-scope errors.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        ConfigSpec::from_path(path)?.try_into()
    }

    /// Reads runtime YAML using the CLI geodata-mode default.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file, specification or runtime-scope errors.
    pub fn from_path_with_geodata_mode(
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_path_with_geodata_mode(path, geodata_mode)?.try_into()
    }

    /// Re-reads one configured local proxy-provider and rebuilds dependent
    /// selector membership without changing the active value on failure.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for missing providers, file/YAML failures,
    /// unsupported proxy records or duplicate names.
    pub fn reload_proxy_provider(&self, name: &str) -> Result<Self, ConfigError> {
        let index = self
            .proxy_providers
            .iter()
            .position(|provider| provider.name == name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
        let path = self.proxy_providers[index].path.clone();
        let proxies = load_proxy_provider_file(
            name,
            &path,
            &self.proxy_providers[index].transform,
            self.home_directory.as_deref(),
        )?;
        self.replace_proxy_provider(index, proxies)
    }

    /// Parses downloaded provider YAML and rebuilds every dependent group.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] without changing this generation when the
    /// payload is invalid or introduces duplicate proxy names.
    pub fn replace_proxy_provider_source(
        &self,
        name: &str,
        source: &str,
    ) -> Result<Self, ConfigError> {
        let index = self
            .proxy_providers
            .iter()
            .position(|provider| provider.name == name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
        let proxies = parse_proxy_provider_source(
            name,
            source,
            &self.proxy_providers[index].transform,
            self.home_directory.as_deref(),
        )?;
        self.replace_proxy_provider(index, proxies)
    }

    fn replace_proxy_provider(
        &self,
        index: usize,
        proxies: Vec<ProxyConfig>,
    ) -> Result<Self, ConfigError> {
        let mut next = self.clone();
        let name = next.proxy_providers[index].name.clone();
        let mut occupied: BTreeSet<_> = next
            .proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .chain(
                next.proxy_providers
                    .iter()
                    .enumerate()
                    .filter(|(candidate, _)| *candidate != index)
                    .flat_map(|(_, provider)| {
                        provider.proxies.iter().map(|proxy| proxy.name.clone())
                    }),
            )
            .collect();
        if proxies
            .iter()
            .any(|proxy| !occupied.insert(proxy.name.clone()))
        {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        next.proxy_providers[index].proxies = proxies;
        let providers = next.proxy_providers.clone();
        let group_types: BTreeMap<_, _> = next
            .proxy_groups
            .iter()
            .map(|group| {
                let kind = match group.kind {
                    ProxyGroupKind::Select => "Selector",
                    ProxyGroupKind::Fallback => "Fallback",
                    ProxyGroupKind::UrlTest => "URLTest",
                    ProxyGroupKind::LoadBalance => "LoadBalance",
                };
                (group.name.clone(), kind.to_owned())
            })
            .collect();
        let proxy_types = proxy_member_types(&next.proxies, &providers, &group_types);
        for group in &mut next.proxy_groups {
            group.proxies = expand_proxy_group(group, &providers, &proxy_types)?;
        }
        Ok(next)
    }

    /// Re-reads a file rule provider and rebuilds the active rule program.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] without mutating this generation when the file,
    /// provider format or rebuilt rule program is invalid.
    pub fn reload_rule_provider(&self, name: &str) -> Result<Self, ConfigError> {
        let provider = self
            .rule_providers
            .get(name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
        if provider.vehicle == RuleProviderVehicle::Inline {
            let mut next = self.clone();
            if let Some(provider) = next.rule_providers.get_mut(name) {
                provider.cache_modified = Some(SystemTime::now());
            }
            return Ok(next);
        }
        let payload = load_rule_provider_file(&provider.path, provider.format, provider.behavior)?;
        self.replace_rule_provider_payload(name, payload)
    }

    /// Parses downloaded rule-provider bytes and rebuilds the active rules.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] while preserving this generation when parsing or
    /// rule-program validation fails.
    pub fn replace_rule_provider_source(
        &self,
        name: &str,
        source: &[u8],
    ) -> Result<Self, ConfigError> {
        let provider = self
            .rule_providers
            .get(name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
        let payload = parse_rule_provider_source(source, provider.format, provider.behavior)?;
        self.replace_rule_provider_payload(name, payload)
    }

    fn replace_rule_provider_payload(
        &self,
        name: &str,
        payload: Vec<String>,
    ) -> Result<Self, ConfigError> {
        let mut next = self.clone();
        let provider = next
            .rule_providers
            .get_mut(name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
        provider.domains = payload
            .iter()
            .filter_map(|entry| parse_rule_provider_domain(provider.behavior, entry).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        provider.payload = payload;
        provider.cache_modified = Some(SystemTime::now());
        let targets = next
            .proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .chain(next.proxy_groups.iter().map(|group| group.name.clone()))
            .collect();
        let definitions = next
            .rule_providers
            .iter()
            .map(|(name, provider)| {
                (
                    name.clone(),
                    ProviderDefinition {
                        behavior: provider.behavior,
                        payload: provider.payload.clone(),
                    },
                )
            })
            .collect();
        next.rules = RuleSet::parse_with_targets_and_providers(
            &next.raw_rules,
            &next.raw_sub_rules,
            &next.rematches,
            &targets,
            &definitions,
        )?;
        Ok(next)
    }

    #[must_use]
    pub fn has_custom_global_group(&self) -> bool {
        self.proxy_groups.iter().any(|group| group.name == "GLOBAL")
    }

    #[must_use]
    pub fn default_global_proxies(&self) -> Vec<String> {
        let mut names = vec!["DIRECT".to_owned(), "REJECT".to_owned()];
        names.extend(self.proxies.iter().map(|proxy| proxy.name.clone()));
        names.extend(
            self.proxy_groups
                .iter()
                .filter(|group| group.name != "GLOBAL")
                .map(|group| group.name.clone()),
        );
        names
    }

    #[must_use]
    pub fn rematch(&self, name: &str) -> Option<&RematchSpec> {
        self.rematches.iter().find(|rematch| rematch.name == name)
    }

    /// Converts the parsed integer into a bindable runtime port.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidRuntimePort`] for zero or values outside
    /// the unsigned 16-bit port range.
    pub fn listener_port(&self) -> Result<u16, ConfigError> {
        u16::try_from(self.mixed_port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or(ConfigError::InvalidRuntimePort(self.mixed_port))
    }

    /// Returns every configured Phase 3A TCP listener after validating ports.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidRuntimePort`] for a nonzero port outside
    /// the unsigned 16-bit range or when no local listener is configured.
    pub fn listener_ports(&self) -> Result<Vec<(ListenerKind, u16)>, ConfigError> {
        let mut listeners = Vec::new();
        for (kind, value) in [
            (ListenerKind::Http, self.port),
            (ListenerKind::Socks, self.socks_port),
            (ListenerKind::Mixed, self.mixed_port),
        ] {
            if value == 0 {
                continue;
            }
            let port = u16::try_from(value)
                .ok()
                .filter(|port| *port != 0)
                .ok_or(ConfigError::InvalidRuntimePort(value))?;
            listeners.push((kind, port));
        }
        for shadowsocks in &self.shadowsocks_listeners {
            listeners.push((ListenerKind::Shadowsocks, shadowsocks.listen.port()));
        }
        if listeners.is_empty() && self.dns.is_none() {
            return Err(ConfigError::InvalidRuntimePort(0));
        }
        Ok(listeners)
    }

    #[must_use]
    pub fn shadowsocks_listener_for_port(&self, port: u16) -> Option<&ShadowsocksInboundConfig> {
        self.shadowsocks_listeners
            .iter()
            .find(|listener| listener.listen.port() == port)
    }

    /// Returns the bind address for a legacy Shadowsocks inbound listener on the given port.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInbound`] when no Shadowsocks inbound is configured for the port.
    pub fn shadowsocks_listen_address(&self, port: u16) -> Result<SocketAddr, ConfigError> {
        self.shadowsocks_listener_for_port(port)
            .map(|config| config.listen)
            .ok_or_else(|| {
                ConfigError::InvalidInbound(format!(
                    "shadowsocks inbound is not configured on port {port}"
                ))
            })
    }

    /// Resolves the fixed local listener bind address for one configured port.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInbound`] for a non-IP explicit address.
    pub fn listener_address(&self, port: u16) -> Result<SocketAddr, ConfigError> {
        if !self.allow_lan {
            return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
        if self.bind_address == "*" {
            return Ok(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port));
        }
        self.bind_address
            .strip_prefix('[')
            .and_then(|address| address.strip_suffix(']'))
            .unwrap_or(&self.bind_address)
            .parse::<IpAddr>()
            .map(|address| SocketAddr::new(address, port))
            .map_err(|_| {
                ConfigError::InvalidInbound(format!(
                    "bind-address is not an IP address: {}",
                    self.bind_address
                ))
            })
    }

    #[must_use]
    pub fn permits_inbound(&self, address: IpAddr) -> bool {
        let address = canonical_inbound_address(address);
        self.lan_allowed_ips
            .iter()
            .any(|network| network.contains(&address))
            && !self
                .lan_disallowed_ips
                .iter()
                .any(|network| network.contains(&address))
    }

    #[must_use]
    pub fn skips_inbound_auth(&self, address: IpAddr) -> bool {
        let address = canonical_inbound_address(address);
        self.skip_auth_prefixes
            .iter()
            .any(|network| network.contains(&address))
    }

    /// Applies validated controller updates to the three inbound prefix sets.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInbound`] when any supplied value is not
    /// an IP prefix.
    pub fn update_inbound_prefixes(
        &mut self,
        skip_auth: Option<Vec<String>>,
        allowed: Option<Vec<String>>,
        disallowed: Option<Vec<String>>,
    ) -> Result<(), ConfigError> {
        if let Some(records) = skip_auth {
            self.skip_auth_prefixes = parse_inbound_prefixes(records, "skip-auth-prefixes")?;
        }
        if let Some(records) = allowed {
            self.lan_allowed_ips = parse_inbound_prefixes(records, "lan-allowed-ips")?;
        }
        if let Some(records) = disallowed {
            self.lan_disallowed_ips = parse_inbound_prefixes(records, "lan-disallowed-ips")?;
        }
        Ok(())
    }

    /// Parses the optional Phase 3B TCP controller address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidControllerAddress`] when the configured
    /// address is not an explicit socket address.
    pub fn controller_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        if self.external_controller.is_empty() {
            return Ok(None);
        }
        self.external_controller
            .parse()
            .map(Some)
            .map_err(|_| ConfigError::InvalidControllerAddress(self.external_controller.clone()))
    }

    /// Parses every network controller endpoint declared by the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidControllerAddress`] for an invalid TCP/TLS address.
    pub fn controller_tcp_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        self.controller_addr()
    }

    /// Parses the optional TLS controller address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidControllerAddress`] for an invalid address.
    pub fn controller_tls_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        if self.external_controller_tls.is_empty() {
            return Ok(None);
        }
        self.external_controller_tls.parse().map(Some).map_err(|_| {
            ConfigError::InvalidControllerAddress(self.external_controller_tls.clone())
        })
    }

    #[must_use]
    pub fn controller_unix_path(&self) -> Option<PathBuf> {
        (!self.external_controller_unix.is_empty()).then(|| {
            let path = PathBuf::from(&self.external_controller_unix);
            if path.is_absolute() {
                path
            } else {
                self.home_directory
                    .as_deref()
                    .unwrap_or_else(|| Path::new("."))
                    .join(path)
            }
        })
    }

    #[must_use]
    pub fn external_ui_path(&self) -> Option<PathBuf> {
        (!self.external_ui.is_empty()).then(|| {
            let path = PathBuf::from(&self.external_ui);
            let base = self
                .home_directory
                .as_deref()
                .unwrap_or_else(|| Path::new("."));
            let path = if path.is_absolute() {
                path
            } else {
                base.join(path)
            };
            if self.external_ui_name.is_empty() {
                path
            } else {
                path.join(&self.external_ui_name)
            }
        })
    }

    #[must_use]
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    #[must_use]
    pub fn home_directory(&self) -> Option<&Path> {
        self.home_directory.as_deref()
    }

    #[must_use]
    pub fn uses_rule_kind(&self, expected: &str) -> bool {
        self.raw_rules
            .iter()
            .chain(self.raw_sub_rules.values().flatten())
            .any(|rule| {
                rule.split(',')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case(expected))
            })
    }

    /// Parses an inline controller replacement using the original resource roots.
    ///
    /// # Errors
    ///
    /// Returns the ordinary configuration parse/runtime errors.
    pub fn replacement_from_yaml(&self, source: &str) -> Result<Self, ConfigError> {
        let home = self
            .home_directory
            .as_deref()
            .unwrap_or_else(|| Path::new("."));
        let source_path = self
            .source_path
            .as_deref()
            .unwrap_or_else(|| Path::new("config.yaml"));
        Self::from_yaml_at_path_with_provider_directory(
            source,
            source_path,
            home,
            self.geodata_mode,
        )
    }

    /// Loads an absolute path contained by the configured home directory.
    ///
    /// # Errors
    ///
    /// Rejects relative/out-of-root paths and propagates parse/I/O errors.
    pub fn replacement_from_safe_path(
        &self,
        requested: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        let explicitly_requested = requested.is_some();
        let path = requested.or(self.source_path.as_deref()).ok_or_else(|| {
            ConfigError::UnsupportedRuntime("default config path unavailable".to_owned())
        })?;
        if !path.is_absolute() {
            return Err(ConfigError::InvalidConfigPath);
        }
        let home = self.home_directory.as_deref().ok_or_else(|| {
            ConfigError::UnsupportedRuntime("configuration safe root unavailable".to_owned())
        })?;
        let normalized_home = std::path::absolute(home)?;
        let normalized_path = std::path::absolute(path)?;
        if explicitly_requested && !normalized_path.starts_with(&normalized_home) {
            return Err(ConfigError::UnsafeConfigPath {
                path: normalized_path,
                home: normalized_home,
            });
        }
        let mut replacement = Self::from_yaml_at_path_with_provider_directory(
            &std::fs::read_to_string(&normalized_path)?,
            &normalized_path,
            home,
            self.geodata_mode,
        )?;
        replacement.source_path.clone_from(&self.source_path);
        Ok(replacement)
    }
}

fn parse_mode(value: &str) -> Result<Mode, ConfigError> {
    match value.to_lowercase().as_str() {
        "global" => Ok(Mode::Global),
        "rule" => Ok(Mode::Rule),
        "direct" => Ok(Mode::Direct),
        _ => Err(ConfigError::InvalidMode),
    }
}

fn parse_log_level(value: &str) -> Result<LogLevel, ConfigError> {
    match value.to_lowercase().as_str() {
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warning" => Ok(LogLevel::Warning),
        "error" => Ok(LogLevel::Error),
        "silent" => Ok(LogLevel::Silent),
        _ => Err(ConfigError::InvalidLogLevel),
    }
}

fn parse_authentication(records: Vec<String>) -> Vec<AuthUser> {
    records
        .into_iter()
        .filter_map(|record| {
            let (username, password) = record.split_once(':')?;
            Some(AuthUser {
                username: username.to_owned(),
                password: password.to_owned(),
            })
        })
        .collect()
}

fn parse_inbound_prefixes(records: Vec<String>, field: &str) -> Result<Vec<IpNet>, ConfigError> {
    records
        .into_iter()
        .map(|record| {
            record.parse::<IpNet>().map_err(|_| {
                ConfigError::InvalidInbound(format!("{field} contains invalid prefix {record}"))
            })
        })
        .collect()
}

fn canonical_inbound_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address @ IpAddr::V4(_) => address,
    }
}

fn parse_controller_cors(raw: Option<RawControllerCors>) -> ControllerCors {
    let raw = raw.unwrap_or_default();
    ControllerCors {
        allow_origins: raw.allow_origins.unwrap_or_else(|| vec!["*".to_owned()]),
        allow_private_network: raw.allow_private_network.unwrap_or(true),
    }
}

fn parse_profile(raw: Option<RawProfile>) -> Result<ProfileConfig, ConfigError> {
    let Some(raw) = raw else {
        return Ok(ProfileConfig {
            store_fake_ip: false,
            store_selected: true,
        });
    };
    if let Some(key) = raw.extra.into_keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("profile.{key}")));
    }
    Ok(ProfileConfig {
        store_fake_ip: raw.store_fake_ip.unwrap_or(false),
        store_selected: raw.store_selected.unwrap_or(true),
    })
}

fn parse_ntp(raw: Option<RawNtp>) -> Result<NtpConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    if let Some(key) = raw.extra.into_keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("ntp.{key}")));
    }
    Ok(NtpConfig {
        enable: raw.enable.unwrap_or(false),
        server: raw.server.unwrap_or_else(|| "time.apple.com".to_owned()),
        port: raw.port.unwrap_or(123),
        interval: raw.interval.unwrap_or(30),
        dialer_proxy: raw.dialer_proxy.unwrap_or_default(),
        write_to_system: raw.write_to_system.unwrap_or(false),
    })
}

fn parse_geox_urls(raw: Option<RawGeoXUrls>) -> Result<GeoXUrls, ConfigError> {
    let raw = raw.unwrap_or_default();
    if let Some(key) = raw.extra.into_keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("geox-url.{key}")));
    }
    Ok(GeoXUrls {
        geo_ip: raw.geo_ip.unwrap_or_else(|| {
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"
                .to_owned()
        }),
        mmdb: raw.mmdb.unwrap_or_else(|| {
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
                .to_owned()
        }),
        asn: raw.asn.unwrap_or_else(|| {
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
                .to_owned()
        }),
        geo_site: raw.geo_site.unwrap_or_else(|| {
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
                .to_owned()
        }),
    })
}

fn normalize_geosite_matcher(raw: Option<&str>) -> String {
    match raw.unwrap_or_default() {
        "mph" | "hybrid" => "mph",
        _ => "succinct",
    }
    .to_owned()
}

fn parse_tls(
    raw: Option<RawTls>,
    home_directory: Option<&Path>,
) -> Result<(ControllerTls, Vec<String>), ConfigError> {
    let Some(raw) = raw else {
        return Ok((ControllerTls::default(), Vec::new()));
    };
    if let Some(key) = raw.extra.into_keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("tls.{key}")));
    }
    let certificates = raw.custom_certifactes.unwrap_or_default();
    if certificates
        .iter()
        .any(|certificate| !certificate.contains("-----BEGIN CERTIFICATE-----"))
    {
        return Err(ConfigError::UnsupportedRuntime(
            "Phase 4E accepts only inline tls.custom-certifactes PEM roots".to_owned(),
        ));
    }
    Ok((
        ControllerTls {
            certificate: resolve_controller_pem(
                raw.certificate.unwrap_or_default(),
                home_directory,
            )?,
            private_key: resolve_controller_pem(
                raw.private_key.unwrap_or_default(),
                home_directory,
            )?,
            client_auth_type: raw.client_auth_type.unwrap_or_default(),
            client_auth_cert: resolve_controller_pem(
                raw.client_auth_cert.unwrap_or_default(),
                home_directory,
            )?,
            ech_key: resolve_controller_pem(raw.ech_key.unwrap_or_default(), home_directory)?,
        },
        certificates,
    ))
}

pub(crate) fn resolve_controller_pem(
    value: String,
    home_directory: Option<&Path>,
) -> Result<String, ConfigError> {
    if value.is_empty() || value.contains("-----BEGIN") {
        return Ok(value);
    }
    let path = PathBuf::from(&value);
    let path = if path.is_absolute() {
        path
    } else if let Some(home) = home_directory {
        home.join(path)
    } else {
        return Ok(value);
    };
    if let Some(home) = home_directory {
        let normalized_home = std::path::absolute(home)?;
        let normalized_path = std::path::absolute(&path)?;
        if !normalized_path.starts_with(&normalized_home) {
            return Err(ConfigError::UnsafeConfigPath {
                path: normalized_path,
                home: normalized_home,
            });
        }
    }
    Ok(path.to_string_lossy().into_owned())
}

fn validate_external_ui(
    external_ui: &str,
    external_ui_name: &str,
    home_directory: Option<&Path>,
) -> Result<(), ConfigError> {
    if !external_ui_name.is_empty()
        && (Path::new(external_ui_name).is_absolute()
            || Path::new(external_ui_name)
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir)))
    {
        return Err(ConfigError::UnsupportedRuntime(
            "external-ui-name is not a local path".to_owned(),
        ));
    }
    if !external_ui.is_empty()
        && let Some(home) = home_directory
        && Path::new(external_ui).is_absolute()
    {
        let normalized_home = std::path::absolute(home)?;
        let normalized_path = std::path::absolute(external_ui)?;
        if !normalized_path.starts_with(&normalized_home) {
            return Err(ConfigError::UnsafeConfigPath {
                path: normalized_path,
                home: normalized_home,
            });
        }
    }
    Ok(())
}
