// tls.rs — TLS for `zeno serve --tls` (V0.5).
//
// What this is: the PostgreSQL wire protocol's SSLRequest, answered
// with 'S' instead of 'N', followed by a real TLS 1.2/1.3 handshake
// (rustls, `ring` provider) and the normal protocol running inside
// the encrypted stream. Without `--tls` the server behaves exactly
// as before (SSLRequest -> 'N', plaintext).
//
// **The certificate is SELF-SIGNED — prototype only.** `zeno cert
// generate` creates it with rcgen (ECDSA P-256, SANs `localhost` +
// `127.0.0.1`, valid 1 year from creation). No browser, no `psql`
// with default settings, and no other client will trust it unless
// it is told to (e.g. `sslmode=require` + the cert as a trust root,
// or `sslcert` pinning). **Production needs a certificate from a
// real CA** — a self-signed cert proves the channel is encrypted,
// it does NOT prove the server is who it claims to be (anyone can
// mint a self-signed cert for `localhost`). See the README's bold
// warning. The cert + key files are mode 0600, like `users.json`.
//
// Design notes:
// - No tokio, no async: rustls's blocking `Connection` API is driven
//   by hand. `TlsReader`/`TlsWriter` share one `TlsInner` behind an
//   `Arc<Mutex<..>>` because `pgwire::handle_client` takes a
//   separate reader and writer; the mutex is only ever held inside
//   a single `read`/`write` call, never across calls, so the two
//   halves can never deadlock each other.
// - `ServerConnection::reader().read()` returns
//   `Err(WouldBlock)` — NOT `Ok(0)` — when no decrypted bytes
//   are buffered yet (rustls docs, `Connection::reader`); the
//   read loop treats exactly that as "pull more TLS records with
//   `read_tls`". Only a clean `close_notify` yields `Ok(0)`, and
//   only a `read_tls` returning `Ok(0)` (TCP EOF) is a real close.
// - The TLS handshake is driven once, up front, in `handshake_tls`
//   (read ClientHello, send the server flight). Any handshake bytes
//   the server still owes after `process_new_packets` are flushed
//   with `wants_write`/`write_tls` — both in the handshake and on
//   every later read/write, so a renegotiation-style flight can
//   never stall the connection.
// - The key is loaded through the provider's key parser
//   (`with_single_cert`), which accepts PKCS#8 / SEC1 / RSA PEM —
//   rcgen writes PKCS#8 ("PRIVATE KEY").
// - No channel binding is implemented yet (a client asking for
//   `p=tls-server-end-point` is still rejected by the SCRAM parser
//   in `auth.rs`) — see the README's honest limits.

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Certificate file in the data directory (`zeno cert generate`).
pub const CERT_FILE: &str = "server-cert.pem";
/// Private key file in the data directory. Mode 0600, like `users.json`.
pub const KEY_FILE: &str = "server-key.pem";
/// How long a generated certificate is valid (days from creation).
const CERT_VALID_DAYS: i64 = 365;

fn cert_path(dir: &Path) -> PathBuf {
    dir.join(CERT_FILE)
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join(KEY_FILE)
}

/// Write `bytes` to `path` with mode 0600, refusing to overwrite an
/// existing file (`create_new`) — a cert/key must never be silently
/// replaced while a client has pinned the old one.
#[cfg(unix)]
fn write_file_0600_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    // `create_new` + mode above already made it 0600; set it
    // explicitly anyway so the mode never depends on the umask.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn write_file_0600_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Generate a self-signed certificate + private key for this data
/// directory and store them as `server-cert.pem` / `server-key.pem`
/// (both mode 0600). Refuses to run when either file already
/// exists — delete them first to regenerate (and expect clients
/// that pinned the old cert to reject the new one).
///
/// ECDSA P-256, subject CN "Zeno", SANs `localhost` and `127.0.0.1`
/// (the only addresses this server ever listens on), server-auth
/// extended key usage, valid from one day before creation (m4:
/// clock-skew tolerance) for one year from creation.
pub fn generate_cert(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("cannot create data directory {}: {e}", dir.display()))?;
    if cert_path(dir).exists() || key_path(dir).exists() {
        return Err(format!(
            "a certificate already exists in {} — delete {CERT_FILE} and {KEY_FILE} first to regenerate",
            dir.display()
        ));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("cannot generate key pair: {e}"))?;
    let mut params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .map_err(|e| format!("cannot build certificate parameters: {e}"))?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Zeno");
    params.distinguished_name = name;
    // ECDSA keys sign; the cert is for server authentication only.
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    // m4: backdate `not_before` by one day, so a client whose
    // clock is a little behind the server's (or a cert generated
    // just before midnight UTC) never sees a "not yet valid"
    // certificate. Validity is one year from creation.
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(CERT_VALID_DAYS);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("cannot self-sign certificate: {e}"))?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    write_file_0600_new(&cert_path(dir), cert_pem.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", cert_path(dir).display()))?;
    // If the key write fails, remove the orphaned cert so a retry
    // does not hit the "already exists" refusal above.
    if let Err(e) = write_file_0600_new(&key_path(dir), key_pem.as_bytes()) {
        let _ = fs::remove_file(cert_path(dir));
        return Err(format!("cannot write {}: {e}", key_path(dir).display()));
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Load `server-cert.pem` / `server-key.pem` from the data directory
/// and build the rustls server config (TLS 1.2 + 1.3 safe defaults,
/// no client certificates). Fails with a clear error when the files
/// are missing — the caller tells the operator to run
/// `zeno cert generate` first. Also fails closed when the private
/// key is readable by group/other (m5) or when the certificate is
/// not yet valid / expired (m4): a server that silently serves an
/// expired cert would fail every client handshake with a confusing
/// error instead of one clear error at startup.
pub fn load_server_config(dir: &Path) -> io::Result<Arc<ServerConfig>> {
    let cert_pem = fs::read(cert_path(dir)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "cannot read {}: {e} — run `zeno cert generate` first",
                cert_path(dir).display()
            ),
        )
    })?;
    let key_pem = fs::read(key_path(dir)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "cannot read {}: {e} — run `zeno cert generate` first",
                key_path(dir).display()
            ),
        )
    })?;
    // m5: a private key that group/other can read must never be
    // loaded — refuse, and tell the operator how to fix it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(key_path(dir))
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o777);
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} has permissions {mode:03o} — refusing to load a private key readable by group/other; run `chmod 600 {}`",
                    key_path(dir).display(),
                    key_path(dir).display()
                ),
            ));
        }
    }
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad {CERT_FILE}: {e}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{CERT_FILE} contains no certificate"),
        ));
    }
    // m4: check the certificate's validity window now, at startup,
    // instead of letting every client handshake fail later.
    let (not_before, not_after) = cert_validity(certs[0].as_ref())?;
    let now = time::OffsetDateTime::now_utc();
    if now < not_before {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{CERT_FILE} is not yet valid (not_before {not_before}) — check the system clock, or regenerate it with `zeno cert generate`"
            ),
        ));
    }
    if now > not_after {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{CERT_FILE} expired on {not_after} — delete {CERT_FILE} and {KEY_FILE} and run `zeno cert generate` to make a new one"
            ),
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad {KEY_FILE}: {e}")))?;
    let provider = rustls::crypto::ring::default_provider();
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------
// Minimal DER parsing for the certificate validity window (m4).
//
// No `x509-parser` dependency is pulled in for this one check:
// the validity is at a fixed place in the structure
// (Certificate ::= SEQUENCE { tbsCertificate SEQUENCE {
//   [0] version, INTEGER serial, SEQUENCE algorithm,
//   SEQUENCE issuer, SEQUENCE validity { notBefore, notAfter },
//   ... } }), so a small TLV walker finds it. Only Zulu
// ('Z') UTCTime/GeneralizedTime values are accepted — that is
// what rcgen writes, and what a CA-issued cert for this server
// would carry; anything else fails closed with a clear error
// instead of being silently misread.
// ---------------------------------------------------------------------

/// Read one DER TLV at `pos`: returns (tag, content start,
/// content length, position just past the value).
fn der_tlv(data: &[u8], mut pos: usize) -> io::Result<(u8, usize, usize, usize)> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cannot parse certificate (bad DER)",
        )
    };
    if pos >= data.len() {
        return Err(bad());
    }
    let tag = data[pos];
    pos += 1;
    if pos >= data.len() {
        return Err(bad());
    }
    let first_len = data[pos];
    pos += 1;
    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > 4 || pos + n > data.len() {
            return Err(bad());
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | data[pos + i] as usize;
        }
        pos += n;
        v
    };
    if pos + len > data.len() {
        return Err(bad());
    }
    Ok((tag, pos, len, pos + len))
}

/// The certificate's (not_before, not_after) as UTC datetimes.
fn cert_validity(der: &[u8]) -> io::Result<(time::OffsetDateTime, time::OffsetDateTime)> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cannot parse certificate validity dates — the certificate may be corrupt",
        )
    };
    let (tag, tbs_start, _, _) = der_tlv(der, 0).map_err(|_| bad())?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag, mut pos, _, _) = der_tlv(der, tbs_start).map_err(|_| bad())?;
    if tag != 0x30 {
        return Err(bad());
    }
    // Optional [0] version (present in the v3 certs rcgen writes).
    let (tag, _, _, next) = der_tlv(der, pos).map_err(|_| bad())?;
    if tag == 0xA0 {
        pos = next;
    }
    // INTEGER serial, SEQUENCE algorithm, SEQUENCE issuer — skipped.
    for want in [0x02, 0x30, 0x30] {
        let (tag, _, _, next) = der_tlv(der, pos).map_err(|_| bad())?;
        if tag != want {
            return Err(bad());
        }
        pos = next;
    }
    // SEQUENCE validity { notBefore, notAfter }.
    let (tag, v_start, _, _) = der_tlv(der, pos).map_err(|_| bad())?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag1, s1, l1, next1) = der_tlv(der, v_start).map_err(|_| bad())?;
    let not_before = parse_cert_time(tag1, &der[s1..s1 + l1]).ok_or_else(bad)?;
    let (tag2, s2, l2, _) = der_tlv(der, next1).map_err(|_| bad())?;
    let not_after = parse_cert_time(tag2, &der[s2..s2 + l2]).ok_or_else(bad)?;
    Ok((not_before, not_after))
}

/// Parse one DER time value: UTCTime (0x17, `YYMMDDHHMMSSZ`) or
/// GeneralizedTime (0x18, `YYYYMMDDHHMMSSZ`). Returns None for any
/// other tag or format (including non-Zulu offsets — see
/// `cert_validity`).
fn parse_cert_time(tag: u8, bytes: &[u8]) -> Option<time::OffsetDateTime> {
    let s = std::str::from_utf8(bytes).ok()?;
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 => {
            if s.len() < 12 {
                return None;
            }
            let yy: i32 = s[..2].parse().ok()?;
            // RFC 5280: 00–49 = 2000s, 50–99 = 1900s.
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..])
        }
        0x18 => {
            if s.len() < 14 {
                return None;
            }
            (s[..4].parse::<i32>().ok()?, &s[4..])
        }
        _ => return None,
    };
    if rest.len() < 10 {
        return None;
    }
    let month: u8 = rest[..2].parse().ok()?;
    let day: u8 = rest[2..4].parse().ok()?;
    let hour: u8 = rest[4..6].parse().ok()?;
    let min: u8 = rest[6..8].parse().ok()?;
    let sec: u8 = rest[8..10].parse().ok()?;
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let time = time::Time::from_hms(hour, min, sec).ok()?;
    Some(time::OffsetDateTime::new_in_offset(
        date,
        time,
        time::UtcOffset::UTC,
    ))
}

// ---------------------------------------------------------------------
// One TLS connection, split into a reader half and a writer half.
// ---------------------------------------------------------------------

struct TlsInner {
    conn: ServerConnection,
    sock: TcpStream,
}

/// Send every handshake/TLS flight rustls currently owes.
/// (Destructured borrows: `conn` and `sock` are separate fields
/// of the same struct, so they must be borrowed separately —
/// `inner.conn.write_tls(&mut inner.sock)` does not compile.)
fn flush_tls_flights(inner: &mut TlsInner) -> io::Result<()> {
    let TlsInner { conn, sock } = inner;
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    Ok(())
}

/// The read half of a TLS connection.
pub struct TlsReader(Arc<Mutex<TlsInner>>);

/// The write half of a TLS connection.
pub struct TlsWriter(Arc<Mutex<TlsInner>>);

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // m8: recover from a poisoned lock like every other lock
        // in the server (`pgwire::recover_lock`) — a thread that
        // panicked while holding this lock must not fail every
        // later read/write on the connection with "TLS connection
        // lock poisoned".
        let mut inner = crate::pgwire::recover_lock(&self.0);
        // Split borrows: `conn` and `sock` are separate fields, so
        // `conn.read_tls(&mut sock)` needs them destructured first.
        let TlsInner { conn, sock } = &mut *inner;
        loop {
            match conn.reader().read(buf) {
                Ok(n) => return Ok(n),
                // rustls's `Reader::read` returns
                // `Err(WouldBlock)` — NOT `Ok(0)` — when no
                // decrypted bytes are buffered yet (see the
                // rustls docs on `Connection::reader`). Only a
                // clean `close_notify` (all data read) yields
                // `Ok(0)`. So WouldBlock here means "pull more
                // TLS records off the socket"; anything else is
                // a real error.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match conn.read_tls(sock) {
                        Ok(0) => return Ok(0), // TCP EOF: peer is gone
                        Ok(_) => {
                            conn.process_new_packets().map_err(io::Error::other)?;
                            while conn.wants_write() {
                                conn.write_tls(sock)?;
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // m8: see `TlsReader::read` — recover, don't fail.
        let mut inner = crate::pgwire::recover_lock(&self.0);
        let n = inner.conn.writer().write(buf)?;
        flush_tls_flights(&mut inner)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        // m8: see `TlsReader::read` — recover, don't fail.
        let mut inner = crate::pgwire::recover_lock(&self.0);
        inner.conn.writer().flush()?;
        flush_tls_flights(&mut inner)?;
        inner.sock.flush()
    }
}

impl Drop for TlsWriter {
    fn drop(&mut self) {
        // m7: a clean shutdown sends TLS `close_notify`, so the
        // peer sees a proper EOF instead of a truncated
        // connection (a client that reads after the server is done
        // gets `Ok(0)`, not a "connection reset" surprise).
        // Best effort only: the socket may already be gone, and
        // a `Drop` must never panic. The lock is taken with
        // `try_lock` — if a read/write is in flight on the other
        // half, the notify is skipped rather than blocking the
        // shutdown on it; a poisoned lock is still recovered.
        let mut inner = match self.0.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => {
                eprintln!("tls: WARNING: TLS connection lock was poisoned — recovering to send close_notify");
                p.into_inner()
            }
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        inner.conn.send_close_notify();
        let _ = flush_tls_flights(&mut inner);
    }
}

/// Drive the TLS handshake on an already-accepted socket (the
/// caller has already answered 'S' to the client's SSLRequest).
/// Returns the (reader, writer) halves for `pgwire::handle_client`.
pub fn handshake_tls(
    stream: TcpStream,
    config: &Arc<ServerConfig>,
) -> io::Result<(TlsReader, TlsWriter)> {
    let mut inner = TlsInner {
        conn: ServerConnection::new(Arc::clone(config)).map_err(io::Error::other)?,
        sock: stream,
    };
    // Split borrows for the same reason as in `TlsReader::read`.
    let TlsInner { conn, sock } = &mut inner;
    while conn.is_handshaking() {
        match conn.read_tls(sock) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed the connection during the TLS handshake",
                ));
            }
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        conn.process_new_packets().map_err(io::Error::other)?;
        while conn.wants_write() {
            conn.write_tls(sock)?;
        }
    }
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    let shared = Arc::new(Mutex::new(inner));
    Ok((TlsReader(Arc::clone(&shared)), TlsWriter(shared)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("zeno-tls-test-{name}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn cert_generate_writes_pem_files_and_loads() {
        let dir = tmp_dir("gen");
        generate_cert(&dir).expect("cert generate must work");
        let cert = fs::read_to_string(dir.join(CERT_FILE)).unwrap();
        let key = fs::read_to_string(dir.join(KEY_FILE)).unwrap();
        assert!(
            cert.contains("-----BEGIN CERTIFICATE-----"),
            "cert file must be PEM: {cert}"
        );
        assert!(
            key.contains("-----BEGIN PRIVATE KEY-----"),
            "key file must be PKCS#8 PEM: {key}"
        );
        // The config loads from the generated files (a corrupt or
        // mismatched cert/key would fail here), and the cert PEM
        // parses to exactly one certificate.
        let _config = load_server_config(&dir).expect("generated cert must load");
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(certs.len(), 1, "exactly one certificate must be stored");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn cert_and_key_files_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("mode");
        generate_cert(&dir).unwrap();
        for file in [CERT_FILE, KEY_FILE] {
            let mode = fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{file} must be 0600, got {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cert_generate_refuses_to_overwrite() {
        let dir = tmp_dir("twice");
        generate_cert(&dir).unwrap();
        let err = generate_cert(&dir).expect_err("second generate must fail");
        assert!(err.contains("already exists"), "{err}");
        // The original files are untouched (not replaced).
        assert!(dir.join(CERT_FILE).exists());
        assert!(dir.join(KEY_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_server_config_without_cert_fails() {
        let dir = tmp_dir("missing");
        let err = load_server_config(&dir).expect_err("no cert must fail");
        assert!(
            err.to_string().contains("cert generate"),
            "error must tell the operator to run cert generate: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_cert_is_backdated_one_day() {
        // m4: `not_before` is ~1 day before creation, so a client
        // whose clock runs a little behind never sees "not yet
        // valid". Parse the validity window straight out of the
        // generated certificate with the same DER walker
        // `load_server_config` uses.
        let dir = tmp_dir("backdate");
        generate_cert(&dir).unwrap();
        let cert_pem = fs::read(dir.join(CERT_FILE)).unwrap();
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (not_before, not_after) = cert_validity(certs[0].as_ref()).unwrap();
        let now = time::OffsetDateTime::now_utc();
        assert!(
            not_before <= now - time::Duration::hours(23),
            "not_before must be at least ~1 day in the past, got {not_before} (now {now})"
        );
        assert!(
            not_before > now - time::Duration::days(2),
            "not_before must not be backdated by more than ~1 day, got {not_before}"
        );
        assert!(
            not_after > now + time::Duration::days(364),
            "not_after must be ~1 year out, got {not_after}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Write a certificate + key with custom validity dates into
    /// `dir` (both files mode 0600, like `generate_cert`).
    fn write_cert_with_dates(
        dir: &Path,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) {
        use std::os::unix::fs::PermissionsExt;
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Zeno");
        params.distinguished_name = name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.self_signed(&key_pair).unwrap();
        fs::write(dir.join(CERT_FILE), cert.pem().as_bytes()).unwrap();
        fs::write(dir.join(KEY_FILE), key_pair.serialize_pem().as_bytes()).unwrap();
        for file in [CERT_FILE, KEY_FILE] {
            fs::set_permissions(dir.join(file), fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn load_server_config_refuses_an_expired_cert() {
        // m4: an expired certificate must fail at startup with a
        // clear error, not fail every client handshake later.
        let dir = tmp_dir("expired");
        let now = time::OffsetDateTime::now_utc();
        write_cert_with_dates(
            &dir,
            now - time::Duration::days(2),
            now - time::Duration::days(1),
        );
        let err = load_server_config(&dir).expect_err("an expired cert must fail to load");
        assert!(
            err.to_string().contains("expired"),
            "error must say the certificate expired: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_server_config_refuses_a_not_yet_valid_cert() {
        // m4: a certificate whose validity starts in the future
        // must fail at startup too.
        let dir = tmp_dir("notyet");
        let now = time::OffsetDateTime::now_utc();
        write_cert_with_dates(
            &dir,
            now + time::Duration::days(1),
            now + time::Duration::days(366),
        );
        let err = load_server_config(&dir).expect_err("a not-yet-valid cert must fail to load");
        assert!(
            err.to_string().contains("not yet valid"),
            "error must say the certificate is not yet valid: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn load_server_config_refuses_a_world_readable_key() {
        // m5: a private key readable by group/other must never be
        // loaded — refuse, and say how to fix it.
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("keymode");
        generate_cert(&dir).unwrap();
        fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_server_config(&dir).expect_err("a 0644 key must fail to load");
        assert!(
            err.to_string().contains("chmod 600"),
            "error must tell the operator to chmod 600 the key: {err}"
        );
        // Fixing the mode makes the same files load fine.
        fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        load_server_config(&dir).expect("a 0600 key must load");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tls_lock_recovers_after_poisoning() {
        // m8: the TLS halves lock through `pgwire::recover_lock`
        // (the same recovery every other server lock uses), so a
        // thread that panics while holding the TLS lock must not
        // wedge the connection with "TLS connection lock
        // poisoned". This pins the recovery behaviour of the
        // shared helper the TLS read/write paths call.
        let m = Arc::new(Mutex::new(7u32));
        let poisoner = Arc::clone(&m);
        let handle = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("injected panic while holding the TLS lock");
        });
        assert!(handle.join().is_err(), "the thread must panic");
        assert!(m.is_poisoned(), "the mutex must be poisoned now");
        let guard = crate::pgwire::recover_lock(&m);
        assert_eq!(*guard, 7u32, "poisoned data must survive recovery");
    }
}
