//! Embedded MTA-STS policy selection and bounded HTTPS retrieval.
use dns_resolver::Resolver;
use futures::future::BoxFuture;
use hickory_resolver::proto::rr::Name;
use policy::MtaStsPolicy;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

lruttl::declare_cache! {
/// Optional process-local adapter; Violet runtime supplies its durable cache.
static CACHE: LruCacheWithTtl<Name, document::PolicyDocument>::new("mta_sts_policy", 64 * 1024);
}

/// Public unicast scope shared by policy retrieval and Violet SMTP routing.
pub fn is_public_address(ip: std::net::IpAddr) -> bool {
    http::public_ip(ip)
}

pub mod dns;
pub mod document;
mod http;
pub mod policy;

struct Getter<'a> {
    resolver: &'a dyn Resolver,
}

impl policy::Get for Getter<'_> {
    fn http_get<'a>(&'a self, url: &'a str) -> BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(http::get(url, self.resolver))
    }
}

/// Compatibility adapter using the same selection rules as the durable resolver.
pub async fn get_optional_policy_for_domain(
    domain: &str,
    resolver: &dyn Resolver,
) -> anyhow::Result<Option<Arc<MtaStsPolicy>>> {
    optional_with_getter(domain, resolver, &Getter { resolver }).await
}

pub async fn get_policy_for_domain(
    domain: &str,
    resolver: Option<&dyn Resolver>,
) -> anyhow::Result<Arc<MtaStsPolicy>> {
    match resolver {
        Some(resolver) => get_policy_for_domain_impl(domain, resolver, &Getter { resolver }).await,
        None => {
            let resolver = dns_resolver::get_resolver();
            get_policy_for_domain_impl(
                domain,
                &**resolver,
                &Getter {
                    resolver: &**resolver,
                },
            )
            .await
        }
    }
}

async fn get_policy_for_domain_impl(
    domain: &str,
    resolver: &dyn Resolver,
    getter: &dyn policy::Get,
) -> anyhow::Result<Arc<MtaStsPolicy>> {
    optional_with_getter(domain, resolver, getter)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no applicable MTA-STS policy"))
}

async fn optional_with_getter(
    domain: &str,
    resolver: &dyn Resolver,
    getter: &dyn policy::Get,
) -> anyhow::Result<Option<Arc<MtaStsPolicy>>> {
    let name = Name::from_str_relaxed(domain)?.to_lowercase();
    let cached = CACHE.get(&name);
    let selected = document::resolve_with_getter(domain, resolver, getter, cached.as_ref()).await?;
    let Some(entry) = selected.document else {
        return Ok(None);
    };
    let policy = Arc::new(entry.policy()?);
    if selected.source == document::PolicySource::Https {
        let ttl = entry
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        let expires = Instant::now()
            .checked_add(ttl)
            .ok_or_else(|| anyhow::anyhow!("MTA-STS lifetime overflow"))?;
        CACHE.insert(name, entry, expires.into()).await;
    }
    Ok(Some(policy))
}

#[cfg(test)]
mod violet_sts_qualification;
