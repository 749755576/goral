use crate::AlgorithmOverrides;

const MODERN_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
];

const MODERN_CIPHER: &[&str] = &[
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "chacha20-poly1305@openssh.com",
];

const MODERN_HMAC: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
];

const MODERN_HOST_KEY: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

const LEGACY_KEX: &[&str] = &[
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
];
const LEGACY_CIPHER: &[&str] = &["aes128-cbc", "aes256-cbc", "3des-cbc"];
const LEGACY_HOST_KEY: &[&str] = &["ssh-dss"];

/// Resolve Netcatty's saved algorithm switches into the complete ordered offer.
///
/// Legacy mode only appends fallbacks. A non-empty per-category override replaces
/// that complete category, and the ECDSA kill switch is applied last.
pub(crate) fn effective_algorithms(
    legacy_enabled: bool,
    skip_ecdsa_host_key: bool,
    overrides: &AlgorithmOverrides,
) -> AlgorithmOverrides {
    let mut effective = AlgorithmOverrides {
        kex: owned(MODERN_KEX),
        cipher: owned(MODERN_CIPHER),
        hmac: owned(MODERN_HMAC),
        server_host_key: owned(MODERN_HOST_KEY),
        compress: vec!["none".to_owned()],
    };

    if legacy_enabled {
        append_unique(&mut effective.kex, LEGACY_KEX);
        append_unique(&mut effective.cipher, LEGACY_CIPHER);
        append_unique(&mut effective.server_host_key, LEGACY_HOST_KEY);
        // russh does not implement hmac-md5. SHA-1 and SHA-1 EtM remain
        // available as the supported legacy MAC fallbacks.
    }

    replace_when_non_empty(&mut effective.kex, &overrides.kex);
    replace_when_non_empty(&mut effective.cipher, &overrides.cipher);
    replace_when_non_empty(&mut effective.hmac, &overrides.hmac);
    replace_when_non_empty(&mut effective.server_host_key, &overrides.server_host_key);
    replace_when_non_empty(&mut effective.compress, &overrides.compress);

    if skip_ecdsa_host_key {
        effective
            .server_host_key
            .retain(|name| !name.starts_with("ecdsa-sha2-"));
    }

    effective
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn append_unique(target: &mut Vec<String>, additions: &[&str]) {
    for addition in additions {
        if !target.iter().any(|value| value == addition) {
            target.push((*addition).to_owned());
        }
    }
}

fn replace_when_non_empty(target: &mut Vec<String>, replacement: &[String]) {
    if !replacement.is_empty() {
        target.clone_from(&replacement.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::effective_algorithms;
    use crate::AlgorithmOverrides;

    #[test]
    fn legacy_mode_only_appends_fallbacks() {
        let modern = effective_algorithms(false, false, &AlgorithmOverrides::default());
        let legacy = effective_algorithms(true, false, &AlgorithmOverrides::default());

        assert_eq!(&legacy.kex[..modern.kex.len()], modern.kex);
        assert_eq!(&legacy.cipher[..modern.cipher.len()], modern.cipher);
        assert!(legacy.kex.ends_with(&[
            "diffie-hellman-group14-sha1".to_owned(),
            "diffie-hellman-group1-sha1".to_owned(),
            "diffie-hellman-group-exchange-sha1".to_owned(),
        ]));
        assert!(legacy.cipher.ends_with(&[
            "aes128-cbc".to_owned(),
            "aes256-cbc".to_owned(),
            "3des-cbc".to_owned(),
        ]));
        assert_eq!(legacy.server_host_key.last().unwrap(), "ssh-dss");
    }

    #[test]
    fn non_empty_overrides_replace_categories_and_empty_lists_do_not() {
        let overrides = AlgorithmOverrides {
            kex: vec!["diffie-hellman-group14-sha1".to_owned()],
            cipher: Vec::new(),
            hmac: vec!["hmac-sha1".to_owned()],
            server_host_key: Vec::new(),
            compress: Vec::new(),
        };
        let effective = effective_algorithms(true, false, &overrides);

        assert_eq!(effective.kex, overrides.kex);
        assert_eq!(effective.hmac, overrides.hmac);
        assert!(effective.cipher.len() > 1);
        assert!(effective.server_host_key.len() > 1);
    }

    #[test]
    fn ecdsa_skip_wins_over_an_explicit_override() {
        let overrides = AlgorithmOverrides {
            server_host_key: vec![
                "ecdsa-sha2-nistp256".to_owned(),
                "ssh-ed25519".to_owned(),
                "ecdsa-sha2-nistp521".to_owned(),
            ],
            ..AlgorithmOverrides::default()
        };
        let effective = effective_algorithms(false, true, &overrides);

        assert_eq!(effective.server_host_key, vec!["ssh-ed25519"]);
    }
}
