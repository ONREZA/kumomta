//! Bounded public-Internet HTTPS policy retrieval for Violet.
use dns_resolver::{IpLookupStrategy, Resolver};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

pub(crate) const MAX_POLICY_BYTES: usize = 64 * 1024;

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => {
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

pub(crate) async fn get(url: &str, resolver: &dyn Resolver) -> anyhow::Result<String> {
    tokio::time::timeout(Duration::from_secs(20), get_inner(url, resolver))
        .await
        .map_err(|_| anyhow::anyhow!("MTA-STS DNS/HTTPS deadline exceeded"))?
}

async fn get_inner(url: &str, resolver: &dyn Resolver) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(url)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port_or_known_default() == Some(443)
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/.well-known/mta-sts.txt",
        "invalid MTA-STS HTTPS URL"
    );
    let host = url
        .domain()
        .ok_or_else(|| anyhow::anyhow!("MTA-STS policy host must be DNS"))?;
    anyhow::ensure!(
        host.starts_with("mta-sts.") && host.len() > 8,
        "invalid MTA-STS policy host"
    );
    // Resolve once through the same explicit Kumo resolver as the TXT lookup.
    // Pin every approved address in reqwest, retaining the original TLS SNI /
    // certificate hostname. No getaddrinfo/hosts/proxy or re-resolution fallback.
    let resolved =
        dns_resolver::resolve_a_or_aaaa(host, Some(resolver), IpLookupStrategy::Ipv4AndIpv6)
            .await?;
    anyhow::ensure!(
        !resolved.is_empty() && resolved.len() <= 32,
        "invalid MTA-STS HTTPS address set"
    );
    let mut addresses = BTreeSet::new();
    for address in resolved {
        match address.addr.ip() {
            Some(ip) if public_ip(ip) => {
                addresses.insert(SocketAddr::new(ip, 443));
            }
            _ => anyhow::bail!("non-public MTA-STS HTTPS address rejected"),
        }
    }
    let addresses: Vec<_> = addresses.into_iter().collect();
    let client = client_builder()
        .resolve_to_addrs(host, &addresses)
        .build()?;
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await?;
    anyhow::ensure!(
        response.status() == reqwest::StatusCode::OK,
        "MTA-STS HTTPS status must be 200"
    );
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .ok_or_else(|| anyhow::anyhow!("MTA-STS Content-Type required"))?
        .to_str()?;
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    anyhow::ensure!(
        media_type.eq_ignore_ascii_case("text/plain"),
        "MTA-STS Content-Type must be text/plain"
    );
    if let Some(encoding) = response.headers().get(reqwest::header::CONTENT_ENCODING) {
        anyhow::ensure!(
            encoding.to_str()?.eq_ignore_ascii_case("identity"),
            "encoded MTA-STS policy rejected"
        );
    }
    anyhow::ensure!(
        !response
            .content_length()
            .is_some_and(|size| size > MAX_POLICY_BYTES as u64),
        "MTA-STS policy Content-Length exceeds 64 KiB"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= MAX_POLICY_BYTES,
            "MTA-STS policy stream exceeds 64 KiB"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(body).map_err(|_| anyhow::anyhow!("MTA-STS policy is not UTF-8"))?)
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent("violet-policy/1.0")
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn policy_endpoint_accepts_the_honest_user_agent() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let authenticated_client = String::from_utf8(request)
                .unwrap()
                .to_ascii_lowercase()
                .contains("\r\nuser-agent: violet-policy/1.0\r\n");
            let response = if authenticated_client {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
            };
            stream.write_all(response.as_bytes()).unwrap();
        });
        // Loopback transport is test-only; production always uses https_only.
        let response = client_builder()
            .https_only(false)
            .build()
            .unwrap()
            .get(format!("http://{address}/.well-known/mta-sts.txt"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        server.join().unwrap();
    }

    #[test]
    fn rejects_private_special_and_multicast_policy_targets() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public_v4(address.parse().unwrap()), "{address}");
        }
        assert!(public_v4("217.168.243.68".parse().unwrap()));
    }
}
