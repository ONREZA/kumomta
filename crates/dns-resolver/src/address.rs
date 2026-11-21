use kumo_address::host_or_socket::HostOrSocketAddress;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub name: String,
    pub addr: HostOrSocketAddress,
    /// Whether the address was resolved via a DNSSEC-validated (secure) chain.
    /// Used to decide DANE eligibility for the connection. Defaults to false
    /// for addresses that did not originate from a secure DNS lookup (literals,
    /// inbound peers, etc).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_secure: bool,
}

impl std::fmt::Display for ResolvedAddress {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let addr = format!("{}", self.addr);
        if addr == self.name {
            // likely: unix domain socket path
            write!(fmt, "{addr}")
        } else {
            write!(fmt, "{}/{addr}", self.name)
        }
    }
}
