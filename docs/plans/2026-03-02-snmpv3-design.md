# SNMPv3 Authentication & Encryption Support

## Goal

Add SNMPv3 (authPriv) support alongside existing v2c, so switches requiring
authenticated/encrypted SNMP can be managed by HermitShell.

## Decisions

- **Both v2c and v3** coexist — existing switches unaffected, new switches choose version
- **v3 security level: authPriv only** — authentication + encryption always on for v3
- **Algorithm choice via dropdowns** — auth protocol (SHA256 default) and cipher (AES128 default)
  exposed in UI since switches vary in what they support

## Architecture

Extend the `snmp_switches` table with v3 credential columns. A `version` column
(`2c` or `3`) controls which `snmp2` session constructor to use. For v3, the agent
builds a `Security` struct with the stored credentials and calls
`AsyncSession::new_v3()`.

### DB Schema (migration v13)

```sql
ALTER TABLE snmp_switches ADD COLUMN version TEXT NOT NULL DEFAULT '2c';
ALTER TABLE snmp_switches ADD COLUMN v3_username TEXT;
ALTER TABLE snmp_switches ADD COLUMN v3_auth_protocol TEXT;
ALTER TABLE snmp_switches ADD COLUMN v3_cipher TEXT;
ALTER TABLE snmp_switches ADD COLUMN v3_auth_pass_enc TEXT;
ALTER TABLE snmp_switches ADD COLUMN v3_priv_pass_enc TEXT;
```

v2c switches use `community_enc` (unchanged). v3 switches use the new columns.

### Agent Types

```rust
enum SnmpCredentials {
    V2c { community: String },
    V3 {
        username: String,
        auth_protocol: String,  // sha256, sha1, sha384, sha512, sha224, md5
        cipher: String,         // aes128, aes256, aes192, des
        auth_pass: String,
        priv_pass: String,
    },
}
```

### Session Construction

```rust
match credentials {
    SnmpCredentials::V2c { community } =>
        AsyncSession::new_v2c(&addr, community.as_bytes(), 0).await?,
    SnmpCredentials::V3 { username, auth_protocol, cipher, auth_pass, priv_pass } => {
        let auth_proto = parse_auth_protocol(&auth_protocol);
        let cipher_val = parse_cipher(&cipher);
        let security = Security::new(username.as_bytes(), auth_pass.as_bytes())
            .with_auth(Auth::AuthPriv {
                cipher: cipher_val,
                privacy_password: priv_pass.into_bytes(),
            })
            .with_auth_protocol(auth_proto);
        AsyncSession::new_v3(&addr, 0, security).await?
    }
}
```

### Socket API

`switch_add` request gains optional fields:
- `version`: `"2c"` (default) or `"3"`
- `v3_username`, `v3_auth_pass`, `v3_priv_pass` (required when version=3)
- `v3_auth_protocol` (default: `"sha256"`), `v3_cipher` (default: `"aes128"`)

Auth/priv passwords encrypted with `session_secret` same as community strings.

### Common Types

`SnmpSwitchInfo` gains:
- `version: String`
- `v3_username: Option<String>`
- `v3_auth_protocol: Option<String>`
- `v3_cipher: Option<String>`

Passwords never exposed in `SnmpSwitchInfo`.

### UI

Add-switch form gains SNMP Version dropdown (v2c/v3). When v3 selected:
- Username field
- Auth Password field
- Privacy Password field
- Auth Protocol dropdown (MD5, SHA1, SHA224, SHA256*, SHA384, SHA512)
- Cipher dropdown (DES, AES128*, AES192, AES256)

Switch list table gains a Version column.

### Integration Test

Test 55 extended with a v3 switch_add/switch_list/switch_remove cycle using
test credentials.
