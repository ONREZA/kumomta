use dns_resolver::Resolver;
use std::collections::BTreeMap;

// <https://datatracker.ietf.org/doc/html/rfc8461>

#[derive(Debug)]
pub struct MtaStsDnsRecord {
    pub id: String,
    pub fields: BTreeMap<String, String>,
}

pub async fn resolve_dns_record(
    policy_domain: &str,
    resolver: &dyn Resolver,
) -> anyhow::Result<MtaStsDnsRecord> {
    discover_dns_record(policy_domain, resolver)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no STSv1 TXT record"))
}

pub async fn discover_dns_record(
    policy_domain: &str,
    resolver: &dyn Resolver,
) -> anyhow::Result<Option<MtaStsDnsRecord>> {
    Ok(match discover(policy_domain, resolver).await? {
        Discovery::Record(record) => Some(record),
        Discovery::Absent | Discovery::Invalid => None,
    })
}

pub enum Discovery {
    Record(MtaStsDnsRecord),
    Absent,
    Invalid,
}

pub async fn discover(policy_domain: &str, resolver: &dyn Resolver) -> anyhow::Result<Discovery> {
    let dns_name = format!("_mta-sts.{policy_domain}");
    let answer = resolver.resolve_txt(&dns_name).await?;
    anyhow::ensure!(
        !answer.bogus
            && matches!(
                answer.response_code,
                hickory_resolver::proto::op::ResponseCode::NoError
                    | hickory_resolver::proto::op::ResponseCode::NXDomain
            ),
        "MTA-STS DNS lookup failed"
    );
    Ok(match parse_records(answer.as_txt()) {
        Ok(Some(record)) => Discovery::Record(record),
        Ok(None) => Discovery::Absent,
        Err(_) => Discovery::Invalid,
    })
}

fn parse_records(res: Vec<String>) -> anyhow::Result<Option<MtaStsDnsRecord>> {
    anyhow::ensure!(
        res.len() <= 64 && res.iter().map(String::len).sum::<usize>() <= 16384,
        "MTA-STS TXT answer exceeds bounds"
    );
    // Fragments within one RR have already been joined by Answer::as_txt.
    // Separate RRs must never be concatenated into an invented policy record.
    let mut records = res.iter().filter(|rr| {
        rr.strip_prefix("v=STSv1")
            .is_some_and(|rest| rest.trim_start_matches([' ', '\t']).starts_with(';'))
    });
    let Some(txt) = records.next() else {
        return Ok(None);
    };
    anyhow::ensure!(records.next().is_none(), "multiple STSv1 TXT records");
    anyhow::ensure!(txt.is_ascii(), "STSv1 TXT must be ASCII");
    let mut fields = BTreeMap::new();
    for pair in txt.split(';') {
        let pair = pair.trim_matches([' ', '\t']);
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid STSv1 field"))?;
        let (key, value) = (
            key.trim_matches([' ', '\t']),
            value.trim_matches([' ', '\t']),
        );
        anyhow::ensure!(
            !key.is_empty()
                && key.len() <= 32
                && key.as_bytes()[0].is_ascii_alphanumeric()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                && !value.is_empty()
                && value
                    .bytes()
                    .all(|b| (0x21..=0x3a).contains(&b) || b == 0x3c || (0x3e..=0x7e).contains(&b)),
            "invalid STSv1 field syntax"
        );
        // RFC 8461 3.2: for non-repeated fields, only the first occurrence counts.
        fields
            .entry(key.to_string())
            .or_insert_with(|| value.to_string());
    }
    let id = fields
        .get("id")
        .ok_or_else(|| anyhow::anyhow!("STSv1 id required"))?
        .to_string();
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_alphanumeric()),
        "STSv1 id must contain 1 to 32 ASCII alphanumeric characters"
    );

    Ok(Some(MtaStsDnsRecord { id, fields }))
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use dns_resolver::TestResolver;

    #[tokio::test]
    async fn test_parse_dns_record() {
        let resolver = TestResolver::default().with_txt(
            "_mta-sts.gmail.com",
            "v=STSv1; id=20190429T010101;".to_owned(),
        );

        let result = resolve_dns_record("gmail.com", &resolver).await.unwrap();

        k9::snapshot!(
            result,
            r#"
MtaStsDnsRecord {
    id: "20190429T010101",
    fields: {
        "id": "20190429T010101",
        "v": "STSv1",
    },
}
"#
        );
    }
}
