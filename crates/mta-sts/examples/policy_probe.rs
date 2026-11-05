//! Laboratory HTTPS/cache probe using the actual MTA-STS library. No mail.
use std::io::{self, BufRead, Write};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Each line names a disposable DNS zone file and policy domain. DNS is a
    // native fixture; HTTPS, certificates, body reads and cache are real.
    for line in io::stdin().lock().lines() {
        let line = line?;
        let parts: Vec<_> = line.split_whitespace().collect();
        anyhow::ensure!(parts.len() == 2, "expected domain and zone path");
        let zone = std::fs::read_to_string(parts[1])?;
        let resolver = dns_resolver::TestResolver::default()
            .with_zone(&zone)
            .map_err(anyhow::Error::msg)?;
        match mta_sts::get_policy_for_domain(parts[0], Some(&resolver)).await {
            Ok(policy) => println!(
                "{{\"policy\":\"ok\",\"mode\":\"{:?}\",\"max_age\":{},\"mail_allowed\":{},\"other_allowed\":{}}}",
                policy.mode,
                policy.max_age,
                policy.mx_name_matches("mail.mx.violet.test"),
                policy.mx_name_matches("other.violet.test")
            ),
            Err(error) => {
                let error = format!("{error:#}");
                let category = if error.contains("Content-Length") {
                    "body_length"
                } else if error.contains("stream exceeds") {
                    "body_stream"
                } else if error.contains("non-public") {
                    "address"
                } else if error.contains("deadline") {
                    "deadline"
                } else {
                    "rejected"
                };
                // Never print a remote response, arbitrary diagnostic or body.
                println!("{{\"policy\":\"error\",\"category\":\"{category}\"}}");
            }
        }
        io::stdout().flush()?;
    }
    Ok(())
}
