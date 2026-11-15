// txn.rs — MVCC transactions (V0.6). Design first, code second.
//
// # Design (PostgreSQL MVCC, simplified to snapshot isolation)
//
// Every row version carries `xmin` (the transaction that created it)
// and `xmax` (the transaction that replaced/deleted it, if any).
// A transaction begins with a SNAPSHOT taken at BEGIN: the next
// transaction id to be allocated, plus the set of transactions
// active at that moment. A version is visible to a snapshot when:
//
//   * its `xmin` committed before the snapshot began — i.e. `xmin`
//     is committed AND `xmin < snapshot.next_xid` AND `xmin` was
//     NOT active when the snapshot was taken (a transaction that
//     was running at BEGIN and commits later is still invisible:
//     its data did not exist yet when the snapshot was taken); and
//   * its `xmax` does NOT hide it — `xmax` hides the version only
//     when the deleter committed before the snapshot began too
//     (same rule: committed, `< next_xid`, not active at BEGIN).
//     A deleter that commits AFTER the snapshot began leaves the
//     old version visible to the snapshot; a deleter that never
//     commits (still active, or aborted) hides nothing.
//   * a transaction's OWN versions are always visible to itself
//     (its writes live in its private write buffer, not in the
//     shared chains, so this case never reaches the chain check —
//     but the rule is stated here so the intent is explicit).
//
// The visible value of a key is the NEWEST version in its chain
// that satisfies the rule above. This is SNAPSHOT ISOLATION, not
// PostgreSQL's READ COMMITTED: a statement inside a transaction
// sees the data as of BEGIN, even if another transaction commits
// newer data while this one is still running. Each statement
// outside a transaction is its own tiny transaction (autocommit)
// with a fresh snapshot, so it sees the latest committed data.
//
// # Where versions live
//
// A version chain is stored IN the value slot of its key, as a
// JSON envelope:
//
//   {"__zeno_mvcc":1,"versions":[
//     {"xmin":0,"xmax":3,"v":"old"},
//     {"xmin":3,"xmax":null,"v":null}
//   ]}
//
// (`v: null` is a delete version.) Storing the chain in the value
// means the memtable, SSTables, flush and compaction need no new
// on-disk structures at all: the envelope travels with the key
// like any other value, and the Bloom filter still works on the
// plain key. The price is one JSON parse per versioned read.
// Envelopes written after the V0.6 review carry the
// `ZENO-MVCC2:` prefix (`ENVELOPE_PREFIX`), so a plain value can
// never be mistaken for one by accident; unprefixed envelopes
// from before the fix are trusted only when every id they carry
// is below the engine's `next_txn_id` (see `decode_chain_limited`
// and `Engine::open`) — a forged `xmin: 999999` is rejected and
// read back as the plain text it is.
//
// Migration: values written by V0.5 have no envelope. They decode
// as a single version with `xmin = 0` ("committed before the
// beginning of time"): visible to every snapshot, never a
// conflict. A V0.5 database therefore opens fine under V0.6, and
// its old rows behave as if committed long ago — which they were.
// A V0.5 tombstone (a `None` entry in an SSTable) decodes as a
// single delete version, also `xmin = 0`.
//
// # Transaction ids
//
// `u64`, allocated monotonically by the engine (`next_txn_id`,
// persisted in `meta.json` AND recovered from the WAL on open as
// `max(txn id seen) + 1`, so a crash before the meta save cannot
// reuse an id that reached the WAL). Id `0` is reserved for
// pre-MVCC (V0.5) data. An id is never reused within a run; across
// a restart an id can only be reused if it never wrote anything
// to the WAL — in which case no version and no snapshot can
// reference it, so reuse is harmless.
//
// # Writes, commit, rollback
//
// A transaction's writes live ONLY in its private in-memory write
// buffer (`Txn.writes`: key -> new value or `None` for delete)
// until COMMIT. Nothing is written to the WAL or the memtable
// before commit — so a crash simply loses uncommitted work, which
// is exactly the required behaviour, and ROLLBACK is just
// dropping the buffer.
//
// COMMIT (first-committer-wins): for each key the transaction
// wrote, look at the newest committed version. If it was created
// by a transaction that committed AFTER this transaction's
// snapshot began, another transaction changed this row first —
// the commit fails with 40001 (serialization failure) and the
// transaction is aborted (its buffer is dropped). Otherwise the
// writes are appended to the WAL — one `put`/`del` record per
// write, each tagged with the transaction id, then ONE `commit`
// record — fsynced, then applied to the memtable as new versions
// (the previous newest version gets `xmax = this txn`). A crash
// between the write records and the `commit` record leaves a
// transaction with no commit marker, which replay discards.
//
// An autocommit statement is a one-statement transaction: it gets
// a fresh id, writes its record(s) plus a `commit` record, and
// applies immediately. That costs two WAL fsyncs per `put`/`del`
// instead of V0.5's one — a known, accepted prototype cost
// (see README).
//
// # What this is NOT (honest limits, see README)
// - No two-phase commit, no DDL inside a
//   transaction, no SERIALIZABLE — snapshot isolation only.
//   Savepoints exist since V0.7 (`Txn::savepoints`); they are
//   buffer snapshots only, not sub-transactions.
// - No READ COMMITTED: every statement in a transaction sees
//   the BEGIN snapshot, never newer commits.
// - The committed-transaction set is kept in memory and pruned
//   by `VACUUM` (see `Engine::vacuum`): ids below the oldest
//   live snapshot's watermark are covered by the watermark
//   itself, so they can leave the set. The watermark rule rests
//   on one invariant — no stored version ever references an
//   aborted transaction id, because an aborted transaction's
//   writes never reach a version chain (they live only in its
//   private buffer until COMMIT). Ids aborted in this run are
//   also remembered explicitly, so even a below-watermark id
//   that aborted here never reads as committed.
// - Old versions are vacuumed while the server runs by the
//   `VACUUM` statement (see `Engine::vacuum`): it prunes only
//   versions no live snapshot can see, bounded by the oldest
//   live snapshot's watermark, and prunes the committed set
//   with it. An idle transaction still pins its snapshot, but
//   only until the idle-transaction timeout rolls it back
//   (see `pgwire.rs`). `compact()` (CLI, no live snapshots)
//   prunes each chain to its newest version. A long-running
//   server's chains grow with every update until a VACUUM or a
//   CLI compaction runs.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Transaction id `0`: pre-MVCC (V0.5) data. Always counts as
/// committed, and older than every snapshot.
pub const LEGACY_XID: u64 = 0;

/// Marker key in a versioned value envelope. A stored value that
/// parses as a JSON object with this key (and value `1`) is a
/// version chain, not plain data.
pub const ENVELOPE_KEY: &str = "__zeno_mvcc";

/// Prefix that marks a value slot as a V0.6-fix (post-review)
/// version envelope. NEW envelopes are stored as
/// `ENVELOPE_PREFIX + <envelope JSON>`, so they are unambiguous:
/// a plain value can only be mistaken for an envelope if it was
/// deliberately crafted with this exact prefix AND valid envelope
/// JSON after it. Old (unprefixed) envelopes are still readable
/// through `decode_chain_limited`, which only trusts them when
/// every `xmin`/`xmax` they carry is below a caller-supplied
/// bound (the engine passes its `next_txn_id` — a real version
/// id is always below it, while a forged `xmin: 999999` is not).
/// A V0.5 raw value that happens to be byte-identical to an old
/// envelope whose ids are all below that bound cannot be told
/// apart from a real old envelope — that residual ambiguity is
/// why new envelopes carry this prefix, and why a database with
/// no `meta.json` and no transactional WAL at all trusts NO old
/// envelope (see `Engine::open`).
pub const ENVELOPE_PREFIX: &str = "ZENO-MVCC2:";

/// One row version: created by `xmin`, replaced/deleted by `xmax`
/// (if any). `value: None` is a delete version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub xmin: u64,
    /// `#[serde(default)]` so hand-written or older envelopes
    /// without the field still parse.
    #[serde(default)]
    pub xmax: Option<u64>,
    /// `#[serde(default)]` so a missing `v` parses as a delete.
    #[serde(default)]
    pub value: Option<String>,
}

impl Version {
    pub fn new(xmin: u64, value: Option<String>) -> Self {
        Self {
            xmin,
            xmax: None,
            value,
        }
    }
}

/// The on-disk envelope for one key's version chain.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    #[serde(rename = "__zeno_mvcc")]
    version: u32,
    versions: Vec<Version>,
}

/// A snapshot, taken at BEGIN: the next transaction id to be
/// allocated at that moment, and the transactions active then.
/// A transaction id is "before the snapshot" when it is
/// `< next_xid` and was NOT active when the snapshot was taken.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub next_xid: u64,
    pub active: BTreeSet<u64>,
}

impl Snapshot {
    /// A snapshot of "right now": nothing active is excluded
    /// except the transactions currently running, so it sees the
    /// latest committed data. Used for autocommit statements.
    pub fn current(next_xid: u64, active: BTreeSet<u64>) -> Self {
        Self { next_xid, active }
    }
}

/// One live transaction: its id, its BEGIN snapshot, and its
/// private write buffer (key -> new value, `None` = delete).
/// The buffer is the ONLY place uncommitted writes exist.
#[derive(Debug)]
pub struct Txn {
    pub id: u64,
    pub snapshot: Snapshot,
    pub writes: std::collections::BTreeMap<String, Option<String>>,
    /// Savepoints (V0.7): a stack of named snapshots of the write
    /// buffer, oldest first. `SAVEPOINT <name>` pushes a copy of
    /// the buffer; `ROLLBACK TO SAVEPOINT <name>` restores the
    /// buffer to that copy (dropping every savepoint made after
    /// it, keeping the named one); `RELEASE SAVEPOINT <name>`
    /// drops the named savepoint and every one made after it.
    /// A transaction that ends (COMMIT / ROLLBACK / disconnect)
    /// drops the whole stack with the transaction itself.
    pub savepoints: Vec<Savepoint>,
}

/// One savepoint: its name and the write buffer as it was when the
/// savepoint was established.
#[derive(Debug, Clone)]
pub struct Savepoint {
    pub name: String,
    pub writes: std::collections::BTreeMap<String, Option<String>>,
}

impl Txn {
    pub fn new(id: u64, snapshot: Snapshot) -> Self {
        Self {
            id,
            snapshot,
            writes: std::collections::BTreeMap::new(),
            savepoints: Vec::new(),
        }
    }
}

/// A failed COMMIT: another transaction changed a row this
/// transaction also wrote (first-committer-wins). Reported to
/// the client as SQLSTATE 40001 (serialization failure).
#[derive(Debug)]
pub struct TxnConflict {
    pub key: String,
}

impl std::fmt::Display for TxnConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "could not serialize access due to concurrent update on key '{}' \
             (another transaction committed a change to this row first; \
             this transaction was aborted — retry it)",
            self.key
        )
    }
}

impl std::error::Error for TxnConflict {}

/// What `Engine::commit` can fail with.
/// - `Unknown`: COMMIT of a transaction that is not active
///   (already committed/rolled back, or never begun) — the
///   client gets 25P01 (no active SQL transaction).
/// - `Conflict`: first-committer-wins — the client gets 40001
///   (serialization failure) and the transaction is aborted.
/// - `Io`: the WAL write itself failed — the transaction is
///   aborted too (its records never reached the commit marker,
///   so replay discards them); the client gets XX000.
#[derive(Debug)]
pub enum CommitError {
    Unknown(String),
    Conflict(TxnConflict),
    Io(std::io::Error),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitError::Unknown(msg) => write!(f, "{msg}"),
            CommitError::Conflict(c) => write!(f, "{c}"),
            CommitError::Io(e) => write!(f, "commit failed writing to the WAL: {e}"),
        }
    }
}

impl std::error::Error for CommitError {}

/// Encode a version chain as the envelope string stored in the
/// value slot. An empty chain encodes as a single delete version
/// — a key with no versions at all must not exist, so callers
/// always pass at least one version. The result carries the
/// `ENVELOPE_PREFIX` marker (see above), so it can never be
/// confused with a plain user value.
pub fn encode_chain(versions: &[Version]) -> String {
    let envelope = Envelope {
        version: 1,
        versions: versions.to_vec(),
    };
    format!(
        "{ENVELOPE_PREFIX}{}",
        serde_json::to_string(&envelope).expect("a version chain is valid JSON")
    )
}

/// Decode a stored value: a prefixed envelope becomes its chain;
/// an unprefixed value that parses as an old envelope is trusted
/// (legacy behaviour — see `decode_chain_limited` for the
/// bounded form the engine uses); anything else is a legacy
/// V0.5 value — one version, `xmin = 0`, never superseded.
/// `None` (a legacy tombstone) decodes as one delete version,
/// also `xmin = 0`.
pub fn decode_chain(stored: Option<&str>) -> Vec<Version> {
    decode_chain_limited(stored, None)
}

/// Bounded decode, used by the engine. `max_xid` is the bound
/// for trusting an UNPREFIXED (pre-fix) envelope: `None` trusts
/// any old envelope (the pre-fix behaviour, kept for tests and
/// for databases whose provenance is already established);
/// `Some(n)` trusts an old envelope only when every `xmin` and
/// `xmax` in it is `< n` and the chain is well-formed (see
/// `chain_is_well_formed` — non-decreasing `xmin`s, with the
/// `xmin = 0` exceptions a V0.5 replay legitimately produces).
/// A prefixed envelope is always trusted (its marker makes it
/// unambiguous), subject to the same structural checks. An old
/// envelope that fails the bound or the structural checks is
/// treated as a plain legacy value — the stored text is returned
/// verbatim as one `xmin = 0` version, so a forged
/// `{"__zeno_mvcc":1,"versions":[{"xmin":999999,...,"value":
/// "pwned"}]}` can never inject a version or inflate
/// `next_txn_id`; it just reads back as the JSON text the user
/// actually stored.
pub fn decode_chain_limited(stored: Option<&str>, max_xid: Option<u64>) -> Vec<Version> {
    match stored {
        None => vec![Version::new(LEGACY_XID, None)],
        Some(text) => {
            if let Some(json) = text.strip_prefix(ENVELOPE_PREFIX) {
                return match serde_json::from_str::<Envelope>(json) {
                    Ok(envelope)
                        if envelope.version == 1
                            && !envelope.versions.is_empty()
                            && chain_is_well_formed(&envelope.versions) =>
                    {
                        envelope.versions
                    }
                    _ => vec![Version::new(LEGACY_XID, Some(text.to_string()))],
                };
            }
            match serde_json::from_str::<Envelope>(text) {
                Ok(envelope)
                    if envelope.version == 1
                        && !envelope.versions.is_empty()
                        && chain_is_well_formed(&envelope.versions)
                        && max_xid.is_none_or(|limit| {
                            envelope
                                .versions
                                .iter()
                                .all(|v| v.xmin < limit && v.xmax.is_none_or(|x| x < limit))
                        }) =>
                {
                    envelope.versions
                }
                _ => vec![Version::new(LEGACY_XID, Some(text.to_string()))],
            }
        }
    }
}

/// A chain is well-formed when its `xmin`s are non-decreasing
/// (oldest first, no duplicates) and every `xmax`, when present,
/// is greater than its own version's `xmin` (a deleter always
/// comes after the creator). Two exceptions, both for `xmin = 0`
/// ("before MVCC time"): several V0.5 records for one key
/// legitimately share `xmin 0` — each supersedes the previous —
/// so equal `xmin`s are allowed when they are 0, and a 0 may
/// follow any `xmin` (a V0.5 record can follow an MVCC version
/// in a mixed hand-written WAL); and an `xmax` of 0 is allowed
/// (it is what a superseding V0.5 record writes). Real
/// engine-written chains always satisfy this; a hand-forged
/// envelope with duplicate non-zero `xmin`s, or `xmax <= xmin`,
/// is never trusted as an envelope.
fn chain_is_well_formed(versions: &[Version]) -> bool {
    let mut prev_xmin: Option<u64> = None;
    for v in versions {
        if let Some(prev) = prev_xmin {
            if v.xmin < prev && v.xmin != LEGACY_XID {
                return false;
            }
            if v.xmin == prev && v.xmin != LEGACY_XID {
                return false;
            }
        }
        if let Some(xmax) = v.xmax {
            if xmax <= v.xmin && xmax != LEGACY_XID {
                return false;
            }
        }
        prev_xmin = Some(v.xmin);
    }
    true
}

/// Does `text` parse as an (old or new) envelope at all, before
/// any bound or well-formedness check? The engine uses this to
/// warn loudly when an envelope-shaped value is REJECTED as an
/// envelope and read back as plain data instead.
pub fn looks_like_envelope(text: &str) -> bool {
    let json = text.strip_prefix(ENVELOPE_PREFIX).unwrap_or(text);
    match serde_json::from_str::<Envelope>(json) {
        Ok(envelope) => envelope.version == 1 && !envelope.versions.is_empty(),
        Err(_) => false,
    }
}

/// Merge version chains that may overlap (the same `xmin`
/// appearing in several layers — e.g. a version flushed twice
/// by the old flush bug, or the same version written to two
/// SSTables). The LAST occurrence of an `xmin` wins (it is the
/// newest layer's copy, so its `xmax` is the most up to date),
/// and it takes the position of its last occurrence — so the
/// result keeps the layers' insertion order, which for real
/// chains is oldest-first by `xmin`. (Sorting by `xmin` would
/// be wrong for chains that legitimately hold several `xmin =
/// 0` versions, or a 0 after an MVCC version — see
/// `chain_is_well_formed`.) Callers pass chains
/// oldest-layer-first; the input order decides which copy wins
/// for a duplicated `xmin`.
pub fn dedupe_chain(chains: Vec<Vec<Version>>) -> Vec<Version> {
    let mut out: Vec<Version> = Vec::new();
    let mut index: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for chain in chains {
        for version in chain {
            if let Some(&pos) = index.get(&version.xmin) {
                out.remove(pos);
                // Positions after `pos` shifted down by one.
                for p in index.values_mut() {
                    if *p > pos {
                        *p -= 1;
                    }
                }
            }
            index.insert(version.xmin, out.len());
            out.push(version);
        }
    }
    out
}

/// Is transaction `xid` committed, from the caller's point of
/// view? `is_committed` is supplied by the engine: id `0` and
/// ids below the restart watermark count as committed, as do ids
/// in the engine's committed set. Anything else is active or
/// aborted — both count as NOT committed here.
pub fn is_version_visible(
    version: &Version,
    snapshot: &Snapshot,
    own_xid: Option<u64>,
    is_committed: &dyn Fn(u64) -> bool,
) -> bool {
    // My own version: visible (unless I later replaced it — see
    // the xmax check below, which also covers xmax == own id).
    // Versions of other transactions are visible only when their
    // creator committed before my snapshot began.
    let xmin_visible = match own_xid {
        Some(own) if version.xmin == own => true,
        _ => {
            version.xmin < snapshot.next_xid
                && !snapshot.active.contains(&version.xmin)
                && is_committed(version.xmin)
        }
    };
    if !xmin_visible {
        return false;
    }
    // xmax hides the version only when the deleter is me, or a
    // transaction that committed before my snapshot began.
    // A deleter that commits after my snapshot, or never commits,
    // leaves the old version visible to me.
    match version.xmax {
        None => true,
        Some(xmax) => match own_xid {
            Some(own) if xmax == own => false,
            _ => {
                !(xmax < snapshot.next_xid
                    && !snapshot.active.contains(&xmax)
                    && is_committed(xmax))
            }
        },
    }
}

/// The visible value of a key: the NEWEST version in its chain
/// (chain order is oldest-first) that the snapshot can see.
/// `None` means absent — either no version is visible, or the
/// newest visible version is a delete.
pub fn resolve_visible(
    chain: &[Version],
    snapshot: &Snapshot,
    own_xid: Option<u64>,
    is_committed: &dyn Fn(u64) -> bool,
) -> Option<String> {
    // Newest-first: the first visible version decides.
    for version in chain.iter().rev() {
        if is_version_visible(version, snapshot, own_xid, is_committed) {
            return version.value.clone();
        }
    }
    None
}

/// The newest version in a chain, if any (used for conflict
/// checks and compaction, which do not need visibility rules).
pub fn newest_version(chain: &[Version]) -> Option<&Version> {
    chain.last()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Committed set for tests: 0 (legacy) and 1..=3 committed,
    /// 4 active, 5 aborted.
    fn committed(xid: u64) -> bool {
        matches!(xid, 0..=3)
    }

    fn snap(next_xid: u64, active: &[u64]) -> Snapshot {
        Snapshot {
            next_xid,
            active: active.iter().copied().collect(),
        }
    }

    #[test]
    fn legacy_value_decodes_to_one_visible_version() {
        let chain = decode_chain(Some("{\"name\":\"Sanjay\"}"));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].xmin, LEGACY_XID);
        assert_eq!(chain[0].value.as_deref(), Some("{\"name\":\"Sanjay\"}"));
        // Visible to every snapshot, including one taken at the
        // very start (next_xid 1).
        assert_eq!(
            resolve_visible(&chain, &snap(1, &[]), None, &committed),
            Some("{\"name\":\"Sanjay\"}".to_string())
        );
    }

    #[test]
    fn envelope_round_trips_and_legacy_tombstone_is_a_delete() {
        let versions = vec![
            Version {
                xmin: 1,
                xmax: Some(2),
                value: Some("old".to_string()),
            },
            Version::new(2, None),
        ];
        let encoded = encode_chain(&versions);
        assert_eq!(decode_chain(Some(&encoded)), versions);
        let chain = decode_chain(None);
        assert_eq!(chain, vec![Version::new(LEGACY_XID, None)]);
        assert_eq!(
            resolve_visible(&chain, &snap(9, &[]), None, &committed),
            None
        );
    }

    #[test]
    fn snapshot_hides_data_committed_after_begin() {
        // Txn 1 committed before the snapshot; txn 3 committed
        // after it began (snapshot taken when next_xid was 3).
        let chain = vec![
            Version::new(1, Some("before".to_string())),
            Version {
                xmin: 3,
                xmax: None,
                value: Some("after".to_string()),
            },
        ];
        // The snapshot sees the old version, not the new one.
        assert_eq!(
            resolve_visible(&chain, &snap(3, &[]), None, &committed),
            Some("before".to_string())
        );
        // A later snapshot sees the new one.
        assert_eq!(
            resolve_visible(&chain, &snap(4, &[]), None, &committed),
            Some("after".to_string())
        );
    }

    #[test]
    fn snapshot_hides_data_of_a_txn_active_at_begin() {
        // Txn 2 was active when the snapshot was taken (next 3)
        // and committed later: its version stays invisible.
        let chain = vec![Version::new(2, Some("racy".to_string()))];
        assert_eq!(
            resolve_visible(&chain, &snap(3, &[2]), None, &committed),
            None
        );
        // A snapshot taken after txn 2 committed sees it.
        assert_eq!(
            resolve_visible(&chain, &snap(4, &[]), None, &committed),
            Some("racy".to_string())
        );
    }

    #[test]
    fn delete_committed_after_begin_leaves_old_version_visible() {
        // Created by txn 1, deleted by txn 3 after the snapshot.
        let chain = vec![Version {
            xmin: 1,
            xmax: Some(3),
            value: Some("alive".to_string()),
        }];
        assert_eq!(
            resolve_visible(&chain, &snap(3, &[]), None, &committed),
            Some("alive".to_string())
        );
        // A later snapshot sees the delete.
        assert_eq!(
            resolve_visible(&chain, &snap(4, &[]), None, &committed),
            None
        );
    }

    #[test]
    fn delete_committed_before_begin_hides_the_row() {
        let chain = vec![Version {
            xmin: 1,
            xmax: Some(2),
            value: Some("gone".to_string()),
        }];
        assert_eq!(
            resolve_visible(&chain, &snap(4, &[]), None, &committed),
            None
        );
    }

    #[test]
    fn prefixed_envelope_round_trips_and_is_unambiguous() {
        // New envelopes carry the prefix; a plain value that is
        // merely envelope-shaped JSON is NOT an envelope.
        let versions = vec![
            Version {
                xmin: 1,
                xmax: Some(2),
                value: Some("old".to_string()),
            },
            Version::new(2, Some("new".to_string())),
        ];
        let encoded = encode_chain(&versions);
        assert!(encoded.starts_with(ENVELOPE_PREFIX));
        assert_eq!(decode_chain(Some(&encoded)), versions);
        // The same JSON without the prefix is still readable with
        // no bound (legacy behaviour), but the engine never calls
        // it that way.
        let bare = encoded.strip_prefix(ENVELOPE_PREFIX).unwrap();
        assert_eq!(decode_chain(Some(bare)), versions);
    }

    #[test]
    fn forged_envelope_with_huge_xmin_is_plain_data() {
        // M1: a V0.5-style value shaped like an envelope, with an
        // xmin far above any real transaction id, must read back
        // as the plain text it is — never as a version, and never
        // inflating next_txn_id.
        let forged =
            r#"{"__zeno_mvcc":1,"versions":[{"xmin":999999,"xmax":null,"value":"pwned"}]}"#;
        let chain = decode_chain_limited(Some(forged), Some(73));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].xmin, LEGACY_XID);
        assert_eq!(chain[0].value.as_deref(), Some(forged));
        // With no bound (old behaviour) it would still decode —
        // the bound is what the engine supplies.
        assert_eq!(decode_chain_limited(Some(forged), None)[0].xmin, 999999);
    }

    #[test]
    fn envelope_shaped_value_with_xid_above_bound_is_plain_data() {
        // An envelope whose xmax is at/above the bound is just as
        // suspicious as a huge xmin.
        let forged = r#"{"__zeno_mvcc":1,"versions":[{"xmin":0,"xmax":1,"value":"hidden"}]}"#;
        let chain = decode_chain_limited(Some(forged), Some(1));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].xmin, LEGACY_XID);
        assert_eq!(chain[0].value.as_deref(), Some(forged));
    }

    #[test]
    fn malformed_envelope_chains_are_plain_data() {
        // Duplicate xmin, or xmax <= xmin: never an envelope.
        let dup = r#"{"__zeno_mvcc":1,"versions":[{"xmin":1,"value":"a"},{"xmin":1,"value":"b"}]}"#;
        assert_eq!(
            decode_chain_limited(Some(dup), Some(100))[0].xmin,
            LEGACY_XID
        );
        let bad_xmax = r#"{"__zeno_mvcc":1,"versions":[{"xmin":5,"xmax":5,"value":"a"}]}"#;
        assert_eq!(
            decode_chain_limited(Some(bad_xmax), Some(100))[0].xmin,
            LEGACY_XID
        );
    }

    #[test]
    fn duplicate_xmin_zero_is_a_legal_legacy_chain() {
        // V0.5 replay legitimately produces several `xmin = 0`
        // versions for one key (put then delete): the chain must
        // decode, and dedupe must keep the last of them.
        let legacy =
            r#"{"__zeno_mvcc":1,"versions":[{"xmin":0,"value":"x"},{"xmin":0,"value":null}]}"#;
        let chain = decode_chain_limited(Some(legacy), Some(100));
        assert_eq!(chain.len(), 2);
        let merged = dedupe_chain(vec![chain]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].value, None);
    }

    #[test]
    fn dedupe_chain_keeps_newest_copy_per_xmin() {
        // The old flush bug wrote the same version twice (once
        // with xmax null, once with xmax set): the newest copy
        // wins, and the chain stays sorted oldest-first.
        let old = vec![
            Version::new(1, Some("v1".to_string())),
            Version::new(2, Some("v2".to_string())),
        ];
        let newer = vec![
            Version {
                xmin: 1,
                xmax: Some(2),
                value: Some("v1".to_string()),
            },
            Version::new(2, Some("v2".to_string())),
            Version::new(3, Some("v3".to_string())),
        ];
        let merged = dedupe_chain(vec![old, newer]);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].xmax, Some(2));
        assert_eq!(merged[2].xmin, 3);
    }

    #[test]
    fn uncommitted_and_aborted_writes_are_invisible() {
        // xmin 4 is still active (never committed); xmin 5 aborted.
        let active_chain = vec![Version::new(4, Some("uncommitted".to_string()))];
        assert_eq!(
            resolve_visible(&active_chain, &snap(9, &[4]), None, &committed),
            None
        );
        let aborted_chain = vec![Version::new(5, Some("aborted".to_string()))];
        assert_eq!(
            resolve_visible(&aborted_chain, &snap(9, &[]), None, &committed),
            None
        );
    }
}
