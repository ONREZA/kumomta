//! Policy document resolution with an explicit durable cache owned by Violet.
use crate::{
    dns,
    policy::{self, MtaStsPolicy},
};
use dns_resolver::Resolver;
use std::time::{Duration, SystemTime};

/// Only authenticated HTTPS fetches create/replace these cache entries.
#[derive(Clone, Debug)]
pub struct PolicyDocument {
    pub id: String,
    pub text: String,
    /// Fetch start orders concurrent refreshes; a slow older request cannot win.
    pub fetched_at: SystemTime,
    pub expires_at: SystemTime,
}

impl PolicyDocument {
    pub fn policy(&self) -> anyhow::Result<MtaStsPolicy> {
        MtaStsPolicy::parse(&self.text)
    }
}

/// Selection provenance is independent from discovery/refresh diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicySource {
    Absent,
    Cache,
    Https,
}

/// Bounded, content-free observation; never an SMTP enforcement decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDiagnostic {
    DnsUnavailable,
    InvalidTxt,
    FetchUnavailable,
    InvalidDocument,
}

impl PolicyDiagnostic {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DnsUnavailable => "sts_dns_unavailable",
            Self::InvalidTxt => "sts_invalid_txt",
            Self::FetchUnavailable => "sts_fetch_unavailable",
            Self::InvalidDocument => "sts_invalid_document",
        }
    }
}

pub struct PolicyResolution {
    pub document: Option<PolicyDocument>,
    pub source: PolicySource,
    pub diagnostic: Option<PolicyDiagnostic>,
}

fn retained(
    cached: Option<&PolicyDocument>,
    diagnostic: Option<PolicyDiagnostic>,
) -> PolicyResolution {
    let document = cached
        .filter(|entry| entry.expires_at > SystemTime::now())
        .cloned();
    PolicyResolution {
        source: if document.is_some() {
            PolicySource::Cache
        } else {
            PolicySource::Absent
        },
        document,
        diagnostic,
    }
}

/// RFC 8461: failed discovery/refresh retains only unexpired authenticated policy.
/// Without one, delivery proceeds without STS; MX/TLSA and TLS remain independent.
/// An authenticated zero-age replacement is returned for durable tombstoning.
pub async fn resolve_policy_document(
    domain: &str,
    resolver: &dyn Resolver,
    cached: Option<&PolicyDocument>,
) -> anyhow::Result<PolicyResolution> {
    resolve_with_getter(domain, resolver, &crate::Getter { resolver }, cached).await
}

pub(crate) async fn resolve_with_getter(
    domain: &str,
    resolver: &dyn Resolver,
    getter: &dyn policy::Get,
    cached: Option<&PolicyDocument>,
) -> anyhow::Result<PolicyResolution> {
    let started = SystemTime::now();
    let cached = cached.filter(|entry| entry.expires_at > started);
    if let Some(cached) = cached {
        // Corrupt durable authority is an invariant failure, not policy absence.
        cached.policy()?;
    }
    let record = match dns::discover(domain, resolver).await {
        Ok(dns::Discovery::Record(record)) => record,
        Ok(dns::Discovery::Absent) => return Ok(retained(cached, None)),
        Ok(dns::Discovery::Invalid) => {
            return Ok(retained(cached, Some(PolicyDiagnostic::InvalidTxt)));
        }
        Err(_) => return Ok(retained(cached, Some(PolicyDiagnostic::DnsUnavailable))),
    };
    if cached.is_some_and(|entry| entry.id == record.id && entry.expires_at > SystemTime::now()) {
        return Ok(retained(cached, None));
    }
    let domain = domain.trim_end_matches('.');
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let text = match getter.http_get(&url).await {
        Ok(text) => text,
        Err(_) => return Ok(retained(cached, Some(PolicyDiagnostic::FetchUnavailable))),
    };
    let expires_at = MtaStsPolicy::parse(&text)
        .ok()
        .and_then(|policy| SystemTime::now().checked_add(Duration::from_secs(policy.max_age)));
    let Some(expires_at) = expires_at else {
        return Ok(retained(cached, Some(PolicyDiagnostic::InvalidDocument)));
    };
    Ok(PolicyResolution {
        document: Some(PolicyDocument {
            id: record.id,
            text,
            fetched_at: started,
            expires_at,
        }),
        source: PolicySource::Https,
        diagnostic: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyMode, test::TestGetter};
    use dns_resolver::TestResolver;

    #[tokio::test]
    async fn cold_cache_discovery_failures_are_diagnostic_not_enforcement() {
        for (txt, diagnostic) in [
            ("v=STSv1; id=current", PolicyDiagnostic::FetchUnavailable),
            ("v=STSv1; id=invalid id", PolicyDiagnostic::InvalidTxt),
        ] {
            let resolver = TestResolver::default().with_txt("_mta-sts.cold.test", txt);
            let selected = resolve_with_getter("cold.test", &resolver, &TestGetter::new([]), None)
                .await
                .unwrap();
            assert!(selected.document.is_none());
            assert_eq!(selected.source, PolicySource::Absent);
            assert_eq!(selected.diagnostic, Some(diagnostic));
        }
        let resolver = TestResolver::default().with_servfail("_mta-sts.cold.test");
        let selected = resolve_with_getter("cold.test", &resolver, &TestGetter::new([]), None)
            .await
            .unwrap();
        assert!(selected.document.is_none());
        assert_eq!(selected.diagnostic, Some(PolicyDiagnostic::DnsUnavailable));
    }

    #[tokio::test]
    async fn durable_cache_keeps_policy_on_dns_or_refresh_failure() {
        let resolver = TestResolver::default().with_txt("_mta-sts.durable.test", "v=STSv1; id=new");
        let cached = PolicyDocument {
            id: "old".into(),
            text: "version: STSv1\nmode: enforce\nmx: mx.durable.test\nmax_age: 3600\n".into(),
            fetched_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(300),
        };
        for resolver in [
            &resolver,
            &TestResolver::default(),
            &TestResolver::default().with_servfail("_mta-sts.durable.test"),
        ] {
            let selected = resolve_with_getter(
                "durable.test",
                resolver,
                &TestGetter::new([]),
                Some(&cached),
            )
            .await
            .unwrap()
            .document
            .unwrap();
            assert_eq!(selected.id, "old");
            assert_eq!(selected.expires_at, cached.expires_at);
        }
        let getter = TestGetter::new([(
            "https://mta-sts.durable.test/.well-known/mta-sts.txt",
            "version: STSv1\nmode: none\nmax_age: 0\n",
        )]);
        let replacement = resolve_with_getter("durable.test", &resolver, &getter, Some(&cached))
            .await
            .unwrap()
            .document
            .unwrap();
        assert_eq!(replacement.id, "new");
        assert_eq!(replacement.policy().unwrap().mode, PolicyMode::None);
        assert!(replacement.expires_at <= SystemTime::now());
        assert!(
            resolve_with_getter(
                "durable.test",
                &resolver,
                &TestGetter::new([]),
                Some(&replacement)
            )
            .await
            .unwrap()
            .document
            .is_none()
        );
    }
}
