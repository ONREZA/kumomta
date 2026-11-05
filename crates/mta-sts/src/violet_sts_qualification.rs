//! Compiled inside the pinned mta-sts crate; never part of the runtime policy.
use super::*;
use dns_resolver::TestResolver;
use policy::{PolicyMode, test::TestGetter};

fn observation(name: &str, guarded: bool) {
    let baseline = std::env::var("VIOLET_STS_EXPECT_BASELINE").as_deref() == Ok("1");
    assert_eq!(guarded, !baseline, "unexpected policy boundary: {name}");
    println!("VIOLET_NATIVE_STS name={name} guarded={guarded} baseline={baseline}");
}

#[tokio::test]
async fn cached_policy_remains_authoritative_on_changed_id_fetch_error() {
    let domain = "violet-refresh-error.test";
    let old = TestResolver::default()
        .with_zone("$ORIGIN violet-refresh-error.test.\n_mta-sts 0 IN TXT \"v=STSv1; id=old;\"\n")
        .unwrap();
    let new = TestResolver::default()
        .with_zone("$ORIGIN violet-refresh-error.test.\n_mta-sts 0 IN TXT \"v=STSv1; id=new;\"\n")
        .unwrap();
    let good = TestGetter::new([(
        "https://mta-sts.violet-refresh-error.test/.well-known/mta-sts.txt",
        "version: STSv1\nmode: enforce\nmx: only.violet-refresh-error.test\nmax_age: 3600\n",
    )]);
    let missing = TestGetter::new([]);
    let first = get_policy_for_domain_impl(domain, &old, &good)
        .await
        .unwrap();
    assert_eq!(first.mode, PolicyMode::Enforce);
    let after_failure = get_policy_for_domain_impl(domain, &new, &missing).await;
    let retained = after_failure
        .is_ok_and(|p| p.mode == PolicyMode::Enforce && p.mx == ["only.violet-refresh-error.test"]);
    observation(
        "changed_dns_id_refresh_failure_keeps_unexpired_policy",
        retained,
    );
}

#[test]
fn policy_parser_rejects_oversized_documents() {
    let data = format!(
        "version: STSv1\nmode: enforce\nmx: mail.violet.test\nmax_age: 3600\nx-padding: {}\n",
        "a".repeat(65536)
    );
    observation(
        "policy_body_over_64k_rejected",
        MtaStsPolicy::parse(&data).is_err(),
    );
}

#[test]
fn policy_max_age_is_a_bounded_decimal_before_cache_deadline_math() {
    let data =
        "version: STSv1\nmode: enforce\nmx: mail.violet.test\nmax_age: 18446744073709551615\n";
    observation(
        "policy_lifetime_overflow_rejected",
        MtaStsPolicy::parse(data).is_err(),
    );
}

#[tokio::test]
async fn changed_id_successfully_replaces_old_policy_and_zero_age_is_not_retained() {
    let domain = "violet-cache-replace.test";
    let old = TestResolver::default().with_txt(
        "_mta-sts.violet-cache-replace.test",
        "v=STSv1; id=old;".to_owned(),
    );
    let new = TestResolver::default().with_txt(
        "_mta-sts.violet-cache-replace.test",
        "v=STSv1; id=new;".to_owned(),
    );
    let good = TestGetter::new([(
        "https://mta-sts.violet-cache-replace.test/.well-known/mta-sts.txt",
        "version: STSv1\nmode: enforce\nmx: only.violet.test\nmax_age: 3600\n",
    )]);
    let none = TestGetter::new([(
        "https://mta-sts.violet-cache-replace.test/.well-known/mta-sts.txt",
        "version: STSv1\nmode: none\nmax_age: 0\n",
    )]);
    assert_eq!(
        get_policy_for_domain_impl(domain, &old, &good)
            .await
            .unwrap()
            .mode,
        PolicyMode::Enforce
    );
    assert_eq!(
        get_policy_for_domain_impl(domain, &new, &none)
            .await
            .unwrap()
            .mode,
        PolicyMode::None
    );
    assert!(
        get_policy_for_domain_impl(domain, &new, &TestGetter::new([]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_txt_does_not_invalidate_unexpired_policy() {
    let domain = "violet-cache-missing.test";
    let old = TestResolver::default().with_txt(
        "_mta-sts.violet-cache-missing.test",
        "v=STSv1; id=old;".to_owned(),
    );
    let good = TestGetter::new([(
        "https://mta-sts.violet-cache-missing.test/.well-known/mta-sts.txt",
        "version: STSv1\nmode: enforce\nmx: only.violet.test\nmax_age: 3600\n",
    )]);
    get_policy_for_domain_impl(domain, &old, &good)
        .await
        .unwrap();
    let result = get_policy_for_domain_impl(domain, &TestResolver::default(), &TestGetter::new([]))
        .await
        .unwrap();
    assert_eq!(result.mode, PolicyMode::Enforce);
}

#[tokio::test]
async fn txt_rr_boundaries_first_tags_and_id_syntax_are_enforced() {
    for text in [
        "v=STSv1; id=;",
        "v=STSv1; id=with space;",
        "v=STSv1; id=abcdefghijklmnopqrstuvwxyz1234567;",
    ] {
        let resolver =
            TestResolver::default().with_txt("_mta-sts.violet-txt.test", text.to_owned());
        assert!(
            dns::resolve_dns_record("violet-txt.test", &resolver)
                .await
                .is_err()
        );
    }
    let repeated = TestResolver::default().with_txt(
        "_mta-sts.violet-txt.test",
        "v=STSv1; v=STSv2; id=one; id=two;".to_owned(),
    );
    assert_eq!(
        dns::resolve_dns_record("violet-txt.test", &repeated)
            .await
            .unwrap()
            .id,
        "one"
    );
    let split = TestResolver::default().with_zone("$ORIGIN violet-txt.test.\n_mta-sts 0 IN TXT \"v=STSv1;\" \" id=one;\"\n_mta-sts 0 IN TXT \"unrelated record\"\n").unwrap();
    assert_eq!(
        dns::resolve_dns_record("violet-txt.test", &split)
            .await
            .unwrap()
            .id,
        "one"
    );
    let duplicate = TestResolver::default().with_zone("$ORIGIN violet-txt.test.\n_mta-sts 0 IN TXT \"v=STSv1; id=one;\"\n_mta-sts 0 IN TXT \"v=STSv1; id=two;\"\n").unwrap();
    assert!(
        dns::resolve_dns_record("violet-txt.test", &duplicate)
            .await
            .is_err()
    );
}

#[test]
fn exact_size_and_valid_max_age_boundaries_remain_usable() {
    let first = MtaStsPolicy::parse("version: STSv1\nversion: STSv2\nmode: enforce\nmode: none\nmx: only.violet.test\nmax_age: 3600\nmax_age: 0\n").unwrap();
    assert_eq!(first.mode, PolicyMode::Enforce);
    assert_eq!(first.max_age, 3600);
    let prefix = "version: STSv1\nmode: enforce\nmx: only.violet.test\nmax_age: 9999999999\nx: ";
    let text = format!("{prefix}{}", "a".repeat(65536 - prefix.len()));
    assert_eq!(MtaStsPolicy::parse(&text).unwrap().max_age, 9_999_999_999);
    assert!(MtaStsPolicy::parse(&(text + "a")).is_err());
    for age in ["", "+1", "-1", "00000000000"] {
        assert!(
            MtaStsPolicy::parse(&format!("version: STSv1\nmode: none\nmax_age: {age}\n")).is_err()
        );
    }
}
