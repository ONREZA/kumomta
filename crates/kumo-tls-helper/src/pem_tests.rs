use super::*;

const PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----\nAQ==\n-----END RSA PRIVATE KEY-----\n";
const SEC1: &str = "-----BEGIN EC PRIVATE KEY-----\nAg==\n-----END EC PRIVATE KEY-----\n";
const PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nAw==\n-----END PRIVATE KEY-----\n";
const OTHER_PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nBA==\n-----END PRIVATE KEY-----\n";
const CERT: &str = "-----BEGIN CERTIFICATE-----\nBQ==\n-----END CERTIFICATE-----\n";
const INVALID: &str = "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n";

fn pem(sections: &[&str]) -> Arc<Box<[u8]>> {
    Arc::new(sections.concat().into_bytes().into_boxed_slice())
}

#[tokio::test]
async fn first_key_of_the_preferred_format_is_selected() {
    for (sections, expected) in [
        (&[SEC1, PKCS1, PKCS8, OTHER_PKCS8][..], 3),
        (&[SEC1, PKCS1][..], 1),
        (&[SEC1][..], 2),
    ] {
        let options = TlsOptions {
            private_key_from_pem: Some(pem(sections)),
            ..Default::default()
        };
        assert_eq!(
            options
                .load_private_key()
                .await
                .unwrap()
                .unwrap()
                .secret_der(),
            &[expected]
        );
    }
}

#[tokio::test]
async fn key_and_certificate_readers_validate_the_whole_input() {
    let mut options = TlsOptions {
        certificate_from_pem: Some(pem(&[CERT, PKCS8, CERT])),
        private_key_from_pem: Some(pem(&[PKCS8, INVALID])),
        ..Default::default()
    };
    let certs = options.load_tls_cert().await.unwrap().unwrap();
    assert_eq!(
        certs.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
        vec![&[5][..]; 2]
    );
    assert_eq!(
        options.load_private_key().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    options.certificate_from_pem = Some(pem(&[CERT, INVALID]));
    assert_eq!(
        options.load_tls_cert().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    options.private_key_from_pem = Some(pem(&[CERT]));
    assert_eq!(
        options.load_private_key().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
