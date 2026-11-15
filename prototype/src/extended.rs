// extended.rs — PostgreSQL extended query protocol (Parse/Bind/
// Describe/Execute/Close/Sync), V0.4. Written from the official
// PostgreSQL docs, "Message Flow" 54.2.3 and "Message Formats" 54.7
// (protocol 3.0). The framing, handshake, Simple Query and SQL
// execution live in `pgwire.rs`; this file only owns the
// prepared-statement / portal state and the six extended messages.
//
// Message map (frontend -> backend replies):
// - Parse 'P' (stmt name, SQL, param type OIDs) -> ParseComplete
//   '1' or ErrorResponse. Exactly ONE statement per Parse; a
//   multi-statement string is a syntax error (42601), unlike Simple
//   Query. Named statements must be Closed before they can be
//   re-Parsed (42P05); the unnamed statement may be re-Parsed.
// - Bind 'B' (portal, statement, param formats, values, result
//   formats) -> BindComplete '2' or ErrorResponse. The value count
//   must match the statement (08P01); named portals must be Closed
//   before re-Bind (42P03); the unnamed portal may be re-Bound.
// - Describe 'D' ('S' statement / 'P' portal) -> Parameter-
//   Description 't' + RowDescription 'T' (or NoData 'n') for a
//   statement; RowDescription or NoData for a portal; ErrorResponse
//   (26000) when the named object does not exist.
// - Execute 'E' (portal, max rows) -> RowDescription + DataRow +
//   CommandComplete, or PortalSuspended 's' when max rows stopped
//   the portal early (another Execute resumes it), or
//   EmptyQueryResponse for an empty statement. Note: strictly, the
//   PostgreSQL docs send RowDescription only on Describe, not on
//   Execute — Zeno repeats it on Execute as well, so a client that
//   skips Describe still learns the column names (this is the
//   "same messages as Simple Query" behaviour of this prototype).
//   Portals bound inside a transaction die when it ends
//   (COMMIT/ROLLBACK/idle-timeout): a later Execute of one fails
//   with 26000 instead of serving its cached rows (B2 — the cache
//   could hold rows that never committed). Since V0.8 a ROLLBACK
//   TO SAVEPOINT also closes every portal AND prepared statement
//   created AFTER that savepoint (26000 on a later use —
//   PostgreSQL behaviour); portals / statements from BEFORE the
//   savepoint survive, and a suspended portal of theirs re-runs
//   fresh on resume (its cache predates the rollback).
// - Close 'C' ('S' statement / 'P' portal) -> CloseComplete '3'.
//   Closing a nonexistent name is NOT an error. Closing a statement
//   also closes every portal built from it.
// - Sync 'S' -> ReadyForQuery 'Z'. The ONLY ReadyForQuery in the
//   extended protocol: never one after Parse/Bind/Describe/
//   Execute/Close, or a pipelined driver desyncs.
// - Flush 'H' -> no reply, just flush (handled in pgwire.rs).
//
// Error recovery (docs 54.2.3): when any extended message fails,
// the backend sends ONE ErrorResponse and then reads and DISCARDS
// every following message until Sync — even a Simple Query in the
// same pipeline is discarded, never run. Sync then sends exactly
// one ReadyForQuery and normal processing resumes. That flag lives
// in `ExtendedState.in_error` and is honoured by the query loop in
// `pgwire.rs`.
//
// A failed Parse drops the stored statement of that name and a
// failed Bind drops the portal of that name (PostgreSQL behaviour):
// the next Bind/Execute then fails with "does not exist" instead
// of silently running the previous statement/portal's query. The
// only exceptions are the duplicate-name errors (42P05/42P03),
// where the stored object is the one being protected, and
// malformed message frames, which never touch stored state.
//
// Parameters: `$1`, `$2`, ... outside strings and quoted
// identifiers. The parameter count is the highest `$n`; gaps are
// an error (42P18, like PostgreSQL). Types: text (OID 25, the
// default when the client leaves a type unspecified or sends 0)
// and int4 (OID 23); any other declared OID is 0A000. Substitution
// happens at the TOKEN level (see `substitute`), never by editing
// the SQL text, so a bound value can never be re-parsed as SQL.
// Values are text format by default; binary format is supported
// for int4 (4 bytes big-endian) and text (raw UTF-8 bytes). Result
// format codes work the same way; binary text columns carry the
// same bytes as text columns (every Zeno column is text, OID 25).
// A bound SQL NULL becomes the empty string — Zeno has no NULLs
// (see README).
//
// What Parse does NOT check (deliberate deviation, see README):
// table/column existence. Parse checks syntax, the statement kind
// and the parameter types only; a SELECT on a missing table fails
// at Bind/Describe/Execute with 42P01 instead, the same code a
// Simple Query would report. PostgreSQL plans the statement at
// Parse and would fail there; Zeno's registry lookup happens when
// the columns are actually needed.

use crate::pgwire::{
    classify_statement, command_complete, data_row, empty_query_response, execute_tokens,
    parse_select, put_i16, put_i32, row_description, split_statements, sql_err, tokenize,
    write_message, Session, Shared, SqlError, StmtKind, StmtOutcome, Token,
};
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::sync::{Arc, Mutex};

/// Type OID for `text` — every Zeno column and every inferred
/// parameter is text.
const OID_TEXT: i32 = 25;
/// Type OID for `int4` — the only other parameter type supported.
const OID_INT4: i32 = 23;
/// PostgreSQL's hard limit on the number of parameters: a
/// ParameterDescription count is an Int16, so more than 32767
/// parameters would wrap negative on the wire. Parse (and Bind,
/// via the i16 value count) reject anything above this.
const MAX_PARAMS: usize = 32767;

/// A prepared statement: the parsed SQL plus its parameter types.
/// The SQL is stored tokenized (from `pgwire::tokenize`) so Execute
/// can substitute bound values at the token level.
#[derive(Debug, Clone)]
struct PreparedStatement {
    tokens: Vec<Token>,
    kind: StmtKind,
    /// One resolved type OID per parameter, in $ order. Length is
    /// the parameter count (the highest `$n` in the SQL).
    param_types: Vec<i32>,
    /// V0.8: the session savepoint clock at Parse time (see
    /// `Session::sp_clock` in `pgwire.rs`). A ROLLBACK TO
    /// SAVEPOINT closes every statement with a clock HIGHER than
    /// the savepoint's — it was created after the savepoint.
    sp_clock: u64,
}

/// Materialized SELECT result, cached in a portal so a
/// PortalSuspended resume returns the same rows (and so a second
/// Execute after completion re-runs the statement fresh instead of
/// re-sending stale rows).
#[derive(Debug, Clone)]
struct CachedRows {
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
    /// B2 (V0.7 review): the session `cache_epoch` this cache
    /// was computed under. A successful ROLLBACK TO SAVEPOINT
    /// bumps the session epoch (it rewound the transaction's
    /// write buffer), so a cache with an older epoch may hold
    /// rows the rollback undid — the next Execute must re-run
    /// the statement instead of serving it.
    epoch: u64,
}

/// A portal: a prepared statement + bound values, ready to execute.
/// `cached` is filled by the first Execute of a SELECT and cleared
/// when the portal completes, so a later Execute re-runs the query.
#[derive(Debug, Clone)]
struct Portal {
    /// Name of the statement this portal was bound from.
    statement_name: String,
    statement: PreparedStatement,
    /// Bound parameter values, in $ order (already decoded to
    /// text; binary int4 arrives canonicalized, e.g. 42 -> "42").
    params: Vec<String>,
    /// One result format code per output column (0 = text,
    /// 1 = binary); empty for statements that return no rows.
    result_formats: Vec<i16>,
    cached: Option<CachedRows>,
    /// Rows already sent from `cached` (for PortalSuspended resume).
    rows_sent: usize,
    /// B2: the transaction (if any) this portal was bound in,
    /// and the session generation at Bind time. A portal bound
    /// inside a transaction dies when that transaction ends
    /// (PostgreSQL closes portals at transaction end): its
    /// cached rows — which may include the transaction's own,
    /// never-committed writes — must never be served again.
    /// `None` means bound outside a transaction; such a portal
    /// survives transaction ends (its cache is a snapshot from
    /// its own first Execute, not a transaction's writes).
    txn_at_bind: Option<u64>,
    gen_at_bind: u64,
    /// V0.8: the session savepoint clock at Bind time (see
    /// `Session::sp_clock` in `pgwire.rs`). A ROLLBACK TO
    /// SAVEPOINT closes every portal with a clock HIGHER than
    /// the savepoint's — it was created after the savepoint, so
    /// a later Execute fails with 26000. A portal with a LOWER
    /// clock survives (its stale cache is re-run via the epoch
    /// in `CachedRows`, like before).
    sp_clock: u64,
}

impl Portal {
    /// Is this portal dead — bound inside a transaction that has
    /// since ended? (B2: serving its cached rows after a
    /// ROLLBACK returned rows that never committed.)
    fn is_dead(&self, session: &Session) -> bool {
        self.txn_at_bind.is_some() && self.gen_at_bind != session.generation
    }
}

/// Per-connection extended-protocol state. Statements and portals
/// live only for this session, never shared across connections.
pub(crate) struct ExtendedState {
    statements: HashMap<String, PreparedStatement>,
    unnamed_statement: Option<PreparedStatement>,
    portals: HashMap<String, Portal>,
    unnamed_portal: Option<Portal>,
    /// True after an extended-protocol error: the query loop
    /// discards every message until Sync (see module docs).
    pub(crate) in_error: bool,
}

impl ExtendedState {
    pub(crate) fn new() -> Self {
        Self {
            statements: HashMap::new(),
            unnamed_statement: None,
            portals: HashMap::new(),
            unnamed_portal: None,
            in_error: false,
        }
    }

    /// A simple Query destroys the unnamed statement and portal
    /// (protocol docs, 54.2.3 note).
    pub(crate) fn clear_unnamed(&mut self) {
        self.unnamed_statement = None;
        self.unnamed_portal = None;
    }

    /// Close every portal (B2): PostgreSQL closes all portals
    /// at transaction end. Prepared statements are NOT closed —
    /// only portals. Called after a Simple Query COMMIT/ROLLBACK
    /// (see `pgwire.rs`) and after an extended COMMIT/ROLLBACK
    /// Execute (see `handle_execute`).
    pub(crate) fn close_all_portals(&mut self) {
        self.portals.clear();
        self.unnamed_portal = None;
    }

    /// Close every portal AND prepared statement created AFTER a
    /// savepoint (V0.8, PostgreSQL behaviour): `cutoff` is the
    /// savepoint's clock, and anything with a HIGHER clock was
    /// created after it. Portals / statements from BEFORE the
    /// savepoint (lower or equal clock) survive. Called after a
    /// successful ROLLBACK TO SAVEPOINT, from `client_loop` (Simple
    /// Query) or `handle_execute` (extended). A later Execute /
    /// Describe / Bind of a closed object fails with 26000 ("does
    /// not exist") — the lookup simply misses, exactly like an
    /// object that was never created.
    pub(crate) fn close_after_savepoint(&mut self, cutoff: u64) {
        self.portals.retain(|_, p| p.sp_clock <= cutoff);
        if self
            .unnamed_portal
            .as_ref()
            .is_some_and(|p| p.sp_clock > cutoff)
        {
            self.unnamed_portal = None;
        }
        self.statements.retain(|_, s| s.sp_clock <= cutoff);
        if self
            .unnamed_statement
            .as_ref()
            .is_some_and(|s| s.sp_clock > cutoff)
        {
            self.unnamed_statement = None;
        }
    }

    fn statement(&self, name: &str) -> Option<&PreparedStatement> {
        if name.is_empty() {
            self.unnamed_statement.as_ref()
        } else {
            self.statements.get(name)
        }
    }

    fn portal(&self, name: &str) -> Option<&Portal> {
        if name.is_empty() {
            self.unnamed_portal.as_ref()
        } else {
            self.portals.get(name)
        }
    }

    fn portal_mut(&mut self, name: &str) -> Option<&mut Portal> {
        if name.is_empty() {
            self.unnamed_portal.as_mut()
        } else {
            self.portals.get_mut(name)
        }
    }

    /// Close a prepared statement; every portal built from it goes
    /// with it (protocol docs, 54.2.3). Closing a nonexistent name
    /// is a no-op, never an error.
    fn close_statement(&mut self, name: &str) {
        if name.is_empty() {
            self.unnamed_statement = None;
        } else {
            self.statements.remove(name);
        }
        self.portals.retain(|_, p| p.statement_name != name);
        if self
            .unnamed_portal
            .as_ref()
            .is_some_and(|p| p.statement_name == name)
        {
            self.unnamed_portal = None;
        }
    }

    fn close_portal(&mut self, name: &str) {
        if name.is_empty() {
            self.unnamed_portal = None;
        } else {
            self.portals.remove(name);
        }
    }
}

// ---------------------------------------------------------------------
// Message-body reader: every malformed frame is a protocol
// violation (08P01), never a panic — a truncated body, a missing
// NUL terminator, or trailing bytes all land here.
// ---------------------------------------------------------------------

struct MsgReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

fn proto(message: &str) -> SqlError {
    sql_err("08P01", format!("protocol violation: {message}"))
}

impl<'a> MsgReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, SqlError> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| proto("truncated message"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_i16(&mut self) -> Result<i16, SqlError> {
        let b = self.read_bytes(2)?;
        Ok(i16::from_be_bytes([b[0], b[1]]))
    }

    fn read_i32(&mut self) -> Result<i32, SqlError> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], SqlError> {
        if self.pos + n > self.buf.len() {
            return Err(proto("truncated message"));
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_cstr(&mut self) -> Result<String, SqlError> {
        let end = self.buf[self.pos..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| proto("unterminated string in message"))?;
        let s = String::from_utf8_lossy(&self.buf[self.pos..self.pos + end]).into_owned();
        self.pos += end + 1;
        Ok(s)
    }

    fn at_end(&self) -> Result<(), SqlError> {
        if self.pos != self.buf.len() {
            return Err(proto("trailing bytes after message body"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Backend messages that only the extended protocol sends.
// ---------------------------------------------------------------------

fn parse_complete(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b'1', &[])
}

fn bind_complete(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b'2', &[])
}

fn close_complete(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b'3', &[])
}

fn portal_suspended(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b's', &[])
}

fn no_data(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b'n', &[])
}

/// ParameterDescription 't': Int16 count, then one Int32 type OID
/// per parameter.
fn parameter_description(writer: &mut impl Write, types: &[i32]) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_i16(&mut body, types.len() as i16);
    for t in types {
        put_i32(&mut body, *t);
    }
    write_message(writer, b't', &body)
}

// ---------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------

/// Find the `$n` placeholders in tokenized SQL. Returns the
/// parameter count (the highest `$n`). A `$n` inside a quoted
/// string or a double-quoted identifier is text, not a parameter.
/// Gaps (`$1` and `$3` but no `$2`) are an error, like PostgreSQL
/// (42P18); `$0`, `$1x` and a bare `$` are syntax errors (42601);
/// more than 32767 parameters is 54000 — a ParameterDescription
/// count is an Int16, so a larger count would wrap negative.
fn scan_params(tokens: &[Token]) -> Result<usize, SqlError> {
    let mut seen = BTreeSet::new();
    for t in tokens {
        if t.quoted_string || t.quoted_ident || !t.text.starts_with('$') {
            continue;
        }
        let digits = &t.text[1..];
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(sql_err(
                "42601",
                format!("invalid parameter placeholder '{}'", t.text),
            ));
        }
        let n: usize = digits.parse().map_err(|_| {
            sql_err(
                "42601",
                format!("invalid parameter placeholder '{}'", t.text),
            )
        })?;
        if n == 0 {
            return Err(sql_err("42601", "there is no parameter $0"));
        }
        if n > MAX_PARAMS {
            return Err(sql_err(
                "54000",
                "too many parameters (maximum 32767 — a ParameterDescription count is an Int16)",
            ));
        }
        seen.insert(n);
    }
    let Some(&max) = seen.iter().next_back() else {
        return Ok(0);
    };
    for k in 1..=max {
        if !seen.contains(&k) {
            return Err(sql_err(
                "42P18",
                format!("could not determine data type of parameter ${k}"),
            ));
        }
    }
    Ok(max)
}

pub(crate) fn handle_parse(
    writer: &mut impl Write,
    _shared: &Arc<Mutex<Shared>>,
    state: &mut ExtendedState,
    session: &mut Session,
    body: &[u8],
) -> Result<(), SqlError> {
    let mut r = MsgReader::new(body);
    let name = r.read_cstr()?;
    let sql = r.read_cstr()?;
    let ntypes = r.read_i16()?;
    if ntypes < 0 {
        return Err(proto("negative parameter type count"));
    }
    let mut declared: Vec<i32> = Vec::new();
    for _ in 0..ntypes {
        declared.push(r.read_i32()?);
    }
    r.at_end()?;

    // The SQL stage: any failure here drops the stored statement
    // of this name (PostgreSQL behaviour — a failed Parse must not
    // leave the previous statement alive to answer a later Bind
    // with silently wrong results). The one exception is the
    // duplicate-name error (42P05): there the stored statement is
    // the one being protected, not a failed replacement, so it
    // stays. Frame-reading errors above return before this point
    // and never touch the stored statement either.
    match parse_statement(state, &name, &sql, &declared) {
        Ok(mut stmt) => {
            // V0.8: stamp the statement with the session clock,
            // so a later ROLLBACK TO SAVEPOINT can tell it was
            // created after that savepoint (higher clock) and
            // close it. The stamp is taken here — after the parse
            // succeeded, so a failed Parse never advances the
            // clock and never disturbs the ordering.
            stmt.sp_clock = session.next_sp_clock();
            if name.is_empty() {
                state.unnamed_statement = Some(stmt);
            } else {
                state.statements.insert(name, stmt);
            }
            parse_complete(writer).map_err(|e| sql_err("XX000", e.to_string()))
        }
        Err(e) => {
            if e.code != "42P05" {
                state.close_statement(&name);
            }
            Err(e)
        }
    }
}

/// Parse and validate one Parse message's SQL: exactly one
/// statement, tokenizable, a supported kind, with in-range
/// parameters and supported declared types. Returns the prepared
/// statement to store. The duplicate-name check runs BEFORE
/// parsing, so a duplicate-name Parse never disturbs the stored
/// statement.
fn parse_statement(
    state: &ExtendedState,
    name: &str,
    sql: &str,
    declared: &[i32],
) -> Result<PreparedStatement, SqlError> {
    // A named statement must be Closed before it can be re-Parsed
    // (docs 54.2.3); the unnamed statement may be re-Parsed. This
    // check runs BEFORE parsing, so a duplicate-name Parse never
    // disturbs the stored statement.
    if !name.is_empty() && state.statements.contains_key(name) {
        return Err(sql_err(
            "42P05",
            format!("prepared statement \"{name}\" already exists"),
        ));
    }

    // Exactly one statement: the extended protocol forbids the
    // multi-statement strings Simple Query accepts (docs 54.2.3).
    let pieces = split_statements(sql);
    let stmts: Vec<&str> = pieces
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if stmts.len() > 1 {
        return Err(sql_err(
            "42601",
            "Parse query string cannot contain more than one statement",
        ));
    }
    let stmt_text = stmts.first().copied().unwrap_or("");
    let tokens =
        tokenize(stmt_text).ok_or_else(|| sql_err("42601", "unterminated string literal"))?;
    let kind = classify_statement(&tokens)?;
    let param_count = scan_params(&tokens)?;

    // Resolve the parameter types. Declared OID 0 = unspecified ->
    // text (25); 25 = text, 23 = int4; anything else is not
    // supported. The declared list may be shorter than the parameter
    // count (the rest are inferred, per the docs); extra entries are
    // ignored.
    let mut param_types = Vec::with_capacity(param_count);
    for i in 0..param_count {
        let oid = declared.get(i).copied().unwrap_or(0);
        let resolved = match oid {
            0 | OID_TEXT => OID_TEXT,
            OID_INT4 => OID_INT4,
            other => {
                return Err(sql_err(
                    "0A000",
                    format!(
                        "unsupported parameter type OID {other} (only text 25 and int4 23 are supported)"
                    ),
                ));
            }
        };
        param_types.push(resolved);
    }

    Ok(PreparedStatement {
        tokens,
        kind,
        param_types,
        // Stamped by `handle_parse` once the parse succeeded
        // (V0.8) — a placeholder here, never left in place.
        sp_clock: 0,
    })
}

// ---------------------------------------------------------------------
// Bind
// ---------------------------------------------------------------------

/// A format-code list from Bind: 0 codes = all text, 1 code = that
/// code for every column/parameter, N codes = one per
/// column/parameter. Anything else is a protocol violation (08P01);
/// a code other than 0 (text) or 1 (binary) is one too.
fn expand_codes(codes: &[i16], count: usize, what: &str) -> Result<Vec<i16>, SqlError> {
    for c in codes {
        if !matches!(c, 0 | 1) {
            return Err(sql_err(
                "08P01",
                format!("invalid {what} format code {c} (only 0=text and 1=binary exist)"),
            ));
        }
    }
    match codes.len() {
        0 => Ok(vec![0; count]),
        1 => Ok(vec![codes[0]; count]),
        n if n == count => Ok(codes.to_vec()),
        n => Err(sql_err(
            "08P01",
            format!("bind message supplies {n} {what} format codes, but {count} are needed"),
        )),
    }
}

/// Decode one bound parameter value. `raw` is None for SQL NULL —
/// Zeno has no NULLs, so NULL becomes the empty string (see README).
/// Text format is UTF-8; binary int4 is 4 bytes big-endian (and is
/// canonicalized to its decimal text); binary text is the raw bytes
/// as UTF-8. A text int4 that does not parse as an i32 is 22P02; a
/// binary int4 of the wrong length is 22P03.
fn decode_param(raw: &Option<Vec<u8>>, ty: i32, format: i16) -> Result<String, SqlError> {
    let Some(bytes) = raw else {
        return Ok(String::new());
    };
    match (ty, format) {
        (OID_INT4, 1) => {
            if bytes.len() != 4 {
                return Err(sql_err(
                    "22P03",
                    format!(
                        "invalid binary representation of int4: {} bytes, expected 4",
                        bytes.len()
                    ),
                ));
            }
            Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string())
        }
        (OID_INT4, 0) => {
            let text = String::from_utf8_lossy(bytes).into_owned();
            text.parse::<i32>().map(|v| v.to_string()).map_err(|_| {
                sql_err(
                    "22P02",
                    format!("invalid input syntax for type integer: \"{text}\""),
                )
            })
        }
        _ => Ok(String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// Output columns of a prepared statement: for SELECT, resolved
/// against the table registry (so Describe can answer without
/// executing); for anything else, None — no rows come back.
fn output_columns(
    shared: &Arc<Mutex<Shared>>,
    stmt: &PreparedStatement,
) -> Result<Option<Vec<String>>, SqlError> {
    match stmt.kind {
        StmtKind::Select => Ok(Some(parse_select(shared, &stmt.tokens)?.columns)),
        _ => Ok(None),
    }
}

pub(crate) fn handle_bind(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    state: &mut ExtendedState,
    session: &mut Session,
    body: &[u8],
) -> Result<(), SqlError> {
    let mut r = MsgReader::new(body);
    let portal_name = r.read_cstr()?;
    let stmt_name = r.read_cstr()?;
    let nfmt = r.read_i16()?;
    if nfmt < 0 {
        return Err(proto("negative parameter format count"));
    }
    let mut fmt_codes = Vec::new();
    for _ in 0..nfmt {
        fmt_codes.push(r.read_i16()?);
    }
    let nparams = r.read_i16()?;
    if nparams < 0 {
        return Err(proto("negative parameter count"));
    }
    let mut raw_params: Vec<Option<Vec<u8>>> = Vec::new();
    for _ in 0..nparams {
        let len = r.read_i32()?;
        if len == -1 {
            raw_params.push(None);
        } else if len < -1 {
            return Err(proto("negative parameter length"));
        } else {
            raw_params.push(Some(r.read_bytes(len as usize)?.to_vec()));
        }
    }
    let nres = r.read_i16()?;
    if nres < 0 {
        return Err(proto("negative result format count"));
    }
    let mut res_codes = Vec::new();
    for _ in 0..nres {
        res_codes.push(r.read_i16()?);
    }
    r.at_end()?;

    // The validation stage: any failure here drops the portal of
    // this name (PostgreSQL behaviour — a failed Bind must not
    // leave the previous portal alive to answer a later Execute
    // with silently wrong results). The one exception is the
    // duplicate-portal error (42P03): there the stored portal is
    // the one being protected, not a failed replacement, so it
    // stays. Frame-reading errors above return before this point
    // and never touch the stored portal either.
    match bind_portal(
        shared,
        state,
        session,
        &portal_name,
        &stmt_name,
        &fmt_codes,
        &raw_params,
        &res_codes,
    ) {
        Ok(portal) => {
            if portal_name.is_empty() {
                state.unnamed_portal = Some(portal);
            } else {
                state.portals.insert(portal_name, portal);
            }
            bind_complete(writer).map_err(|e| sql_err("XX000", e.to_string()))
        }
        Err(e) => {
            if e.code != "42P03" {
                state.close_portal(&portal_name);
            }
            Err(e)
        }
    }
}

/// Validate one Bind message against its prepared statement and
/// build the portal to store. The value count must match the
/// statement, every value must decode, and the result formats are
/// validated against the real column count — in that order, so a
/// bad value (22P02) is reported before a duplicate portal
/// (42P03), matching the previous behaviour.
/// (8 arguments: the message's fields plus the shared state and
/// the session — a struct would only hide them; allowed.)
#[allow(clippy::too_many_arguments)]
fn bind_portal(
    shared: &Arc<Mutex<Shared>>,
    state: &ExtendedState,
    session: &mut Session,
    portal_name: &str,
    stmt_name: &str,
    fmt_codes: &[i16],
    raw_params: &[Option<Vec<u8>>],
    res_codes: &[i16],
) -> Result<Portal, SqlError> {
    let stmt = state.statement(stmt_name).ok_or_else(|| {
        sql_err(
            "26000",
            format!("prepared statement \"{stmt_name}\" does not exist"),
        )
    })?;
    let stmt = stmt.clone();

    // The value count must match the statement (docs 54.2.3).
    if raw_params.len() != stmt.param_types.len() {
        return Err(sql_err(
            "08P01",
            format!(
                "bind message supplies {} parameters, but prepared statement \"{}\" requires {}",
                raw_params.len(),
                stmt_name,
                stmt.param_types.len()
            ),
        ));
    }
    let param_formats = expand_codes(fmt_codes, stmt.param_types.len(), "parameter")?;
    let mut params = Vec::with_capacity(raw_params.len());
    for (i, raw) in raw_params.iter().enumerate() {
        params.push(decode_param(raw, stmt.param_types[i], param_formats[i])?);
    }

    // Result formats are validated against the real column count, so
    // a SELECT on a missing table fails here (42P01), like the
    // planning PostgreSQL does at Bind.
    let out_columns = output_columns(shared, &stmt)?;
    let ncols = out_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    let result_formats = expand_codes(res_codes, ncols, "result")?;

    // A named portal must be Closed before it can be re-Bound
    // (docs 54.2.3); the unnamed portal may be re-Bound.
    if !portal_name.is_empty() && state.portals.contains_key(portal_name) {
        return Err(sql_err(
            "42P03",
            format!("portal \"{portal_name}\" already exists"),
        ));
    }
    Ok(Portal {
        statement_name: stmt_name.to_string(),
        statement: stmt,
        params,
        result_formats,
        cached: None,
        rows_sent: 0,
        // B2: remember the transaction (if any) this portal was
        // bound in, so a later Execute can tell it is dead.
        txn_at_bind: session.txn,
        gen_at_bind: session.generation,
        // V0.8: stamp the portal with the session clock, so a
        // later ROLLBACK TO SAVEPOINT can tell it was created
        // after that savepoint (higher clock) and close it.
        sp_clock: session.next_sp_clock(),
    })
}

// ---------------------------------------------------------------------
// Describe
// ---------------------------------------------------------------------

pub(crate) fn handle_describe(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    state: &mut ExtendedState,
    body: &[u8],
) -> Result<(), SqlError> {
    let mut r = MsgReader::new(body);
    let kind = r.read_byte()?;
    let name = r.read_cstr()?;
    r.at_end()?;
    match kind {
        b'S' => {
            let stmt = state.statement(&name).ok_or_else(|| {
                sql_err(
                    "26000",
                    format!("prepared statement \"{name}\" does not exist"),
                )
            })?;
            let stmt = stmt.clone();
            // Check table/column existence FIRST, before sending
            // anything: a Describe(S) on a missing table used to
            // send ParameterDescription and THEN the ErrorResponse,
            // which a client reads as a half-described statement.
            // Only a successful check sends ParameterDescription
            // followed by RowDescription (or NoData).
            let out_columns = output_columns(shared, &stmt)?;
            parameter_description(writer, &stmt.param_types)
                .map_err(|e| sql_err("XX000", e.to_string()))?;
            match out_columns {
                Some(columns) => {
                    // Formats are zeroes here: Bind has not happened
                    // yet, so the result formats are not known
                    // (docs 54.2.3).
                    row_description(writer, &columns, &[])
                        .map_err(|e| sql_err("XX000", e.to_string()))?;
                }
                None => no_data(writer).map_err(|e| sql_err("XX000", e.to_string()))?,
            }
            Ok(())
        }
        b'P' => {
            let portal = state
                .portal(&name)
                .ok_or_else(|| sql_err("26000", format!("portal \"{name}\" does not exist")))?;
            let (kind, tokens, formats) = (
                portal.statement.kind,
                portal.statement.tokens.clone(),
                portal.result_formats.clone(),
            );
            match kind {
                StmtKind::Select => {
                    let plan = parse_select(shared, &tokens)?;
                    row_description(writer, &plan.columns, &formats)
                        .map_err(|e| sql_err("XX000", e.to_string()))?;
                }
                _ => no_data(writer).map_err(|e| sql_err("XX000", e.to_string()))?,
            }
            Ok(())
        }
        other => Err(sql_err(
            "08P01",
            format!("Describe kind must be 'S' or 'P', got '{}'", other as char),
        )),
    }
}

// ---------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------

/// Replace `$n` placeholder tokens with the bound values. This
/// happens at the TOKEN level, never by editing the SQL text, so a
/// bound value can never be re-parsed as SQL — that is the whole
/// point of parameters. A placeholder token becomes a quoted-string
/// token holding the value.
fn substitute(tokens: &[Token], params: &[String]) -> Vec<Token> {
    tokens
        .iter()
        .map(|t| {
            if !t.quoted_string && !t.quoted_ident && t.text.starts_with('$') {
                if let Ok(n) = t.text[1..].parse::<usize>() {
                    if (1..=params.len()).contains(&n) {
                        return Token {
                            text: params[n - 1].clone(),
                            quoted_string: true,
                            quoted_ident: false,
                        };
                    }
                }
            }
            t.clone()
        })
        .collect()
}

pub(crate) fn handle_execute(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    state: &mut ExtendedState,
    session: &mut Session,
    body: &[u8],
) -> Result<(), SqlError> {
    let mut r = MsgReader::new(body);
    let portal_name = r.read_cstr()?;
    let max_rows = r.read_i32()?;
    r.at_end()?;
    if max_rows < 0 {
        return Err(sql_err("08P01", "Execute max rows must not be negative"));
    }

    // B2: a portal bound inside a transaction that has since
    // ended (COMMIT/ROLLBACK, or an idle-timeout rollback) is
    // DEAD — PostgreSQL closes portals at transaction end. Its
    // cached rows (which may include that transaction's own,
    // never-committed writes) must never be served again, so
    // Execute fails with 26000 ("does not exist") instead of
    // resuming the stale cache.
    let (kind, tokens, params, result_formats, cached, rows_sent) = {
        let portal = state
            .portal(&portal_name)
            .ok_or_else(|| sql_err("26000", format!("portal \"{portal_name}\" does not exist")))?;
        if portal.is_dead(session) {
            return Err(sql_err(
                "26000",
                format!(
                    "portal \"{portal_name}\" does not exist (it was closed at the end of \
                     the transaction it was bound in — re-Bind it to run the query again)"
                ),
            ));
        }
        (
            portal.statement.kind,
            portal.statement.tokens.clone(),
            portal.params.clone(),
            portal.result_formats.clone(),
            portal.cached.clone(),
            portal.rows_sent,
        )
    };
    let generation_before = session.generation;
    // B2: a cache computed before the latest ROLLBACK TO
    // SAVEPOINT is stale — the rollback rewound the write
    // buffer, so the cached rows may include rows that no
    // longer exist. Drop it (keeping `rows_sent`, so the
    // re-run resumes from where the client stopped) and let
    // the first-Execute path below re-run the statement fresh.
    let mut cached = cached;
    if cached
        .as_ref()
        .is_some_and(|c| c.epoch != session.cache_epoch)
    {
        cached = None;
    }
    if kind == StmtKind::Empty {
        empty_query_response(writer).map_err(|e| sql_err("XX000", e.to_string()))?;
        return Ok(());
    }

    // First Execute of this portal: run the statement once and
    // cache a SELECT's rows. A non-SELECT statement runs fresh on
    // every Execute (an INSERT re-inserts, like PostgreSQL); its
    // CommandComplete is the whole reply. The session is passed
    // through so BEGIN/COMMIT/ROLLBACK and statements inside a
    // transaction work over the extended protocol exactly like
    // they do over Simple Query (V0.6). No portal borrow is held
    // across the execution (the statement may end the
    // transaction — and close the portals — itself).
    if cached.is_none() {
        let tokens = substitute(&tokens, &params);
        let outcome = execute_tokens(shared, &tokens, session);
        // A COMMIT/ROLLBACK executed through this portal ended
        // the transaction: close every portal (B2), whether the
        // COMMIT succeeded or failed with 40001.
        if session.generation != generation_before {
            state.close_all_portals();
        }
        // V0.8: a ROLLBACK TO SAVEPOINT executed through this
        // portal closed the portals / statements created after
        // that savepoint — apply the cutoff now.
        if let Some(cutoff) = session.take_savepoint_cutoff() {
            state.close_after_savepoint(cutoff);
        }
        match outcome? {
            StmtOutcome::Rows { columns, rows } => {
                let fresh = CachedRows {
                    columns,
                    rows,
                    epoch: session.cache_epoch,
                };
                cached = Some(fresh.clone());
                // Store the cache back in the portal (it may have
                // been closed above only when a transaction ended
                // — a SELECT never ends one, so it is still here).
                if let Some(portal) = state.portal_mut(&portal_name) {
                    portal.cached = Some(fresh);
                }
            }
            StmtOutcome::Command(tag) => {
                command_complete(writer, &tag).map_err(|e| sql_err("XX000", e.to_string()))?;
                return Ok(());
            }
            StmtOutcome::Empty => {
                empty_query_response(writer).map_err(|e| sql_err("XX000", e.to_string()))?;
                return Ok(());
            }
        }
    }

    // Stream the next slice of the cached rows.
    let cached = cached.expect("cached rows were just filled");
    let total = cached.rows.len();
    // B2: a re-run after a ROLLBACK TO can return FEWER rows
    // than the stale cache held, so `rows_sent` may now be past
    // the end — clamp it instead of slicing out of bounds (the
    // portal then completes with no further rows).
    let start = rows_sent.min(total);
    let end = if max_rows == 0 {
        total
    } else {
        (start + max_rows as usize).min(total)
    };
    let done = end >= total;
    // Execute repeats the RowDescription (see module docs): a
    // client that skipped Describe still learns the columns.
    row_description(writer, &cached.columns, &result_formats)
        .map_err(|e| sql_err("XX000", e.to_string()))?;
    for row in &cached.rows[start..end] {
        data_row(writer, row).map_err(|e| sql_err("XX000", e.to_string()))?;
    }
    if let Some(portal) = state.portal_mut(&portal_name) {
        portal.rows_sent = end;
        if done {
            // Completed: clear the cache so the next Execute of
            // this portal re-runs the statement fresh.
            portal.cached = None;
            portal.rows_sent = 0;
        }
    }
    if done {
        command_complete(writer, &format!("SELECT {total}"))
            .map_err(|e| sql_err("XX000", e.to_string()))?;
    } else {
        portal_suspended(writer).map_err(|e| sql_err("XX000", e.to_string()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------

pub(crate) fn handle_close(
    writer: &mut impl Write,
    state: &mut ExtendedState,
    body: &[u8],
) -> Result<(), SqlError> {
    let mut r = MsgReader::new(body);
    let kind = r.read_byte()?;
    let name = r.read_cstr()?;
    r.at_end()?;
    match kind {
        b'S' => state.close_statement(&name),
        b'P' => state.close_portal(&name),
        other => {
            return Err(sql_err(
                "08P01",
                format!("Close kind must be 'S' or 'P', got '{}'", other as char),
            ));
        }
    }
    // Closing a nonexistent statement or portal is NOT an error
    // (docs 54.2.3) — always CloseComplete.
    close_complete(writer).map_err(|e| sql_err("XX000", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgwire::tokenize;

    fn toks(sql: &str) -> Vec<Token> {
        tokenize(sql).expect("test SQL must tokenize")
    }

    #[test]
    fn close_after_savepoint_keeps_earlier_closes_later() {
        // V0.8: a ROLLBACK TO SAVEPOINT closes every portal and
        // prepared statement with a clock HIGHER than the
        // savepoint's; lower-or-equal clocks survive.
        let mut state = ExtendedState::new();
        let stmt = |clock: u64| PreparedStatement {
            tokens: vec![],
            kind: StmtKind::Select,
            param_types: vec![],
            sp_clock: clock,
        };
        state.statements.insert("old".to_string(), stmt(1));
        state.statements.insert("new".to_string(), stmt(5));
        state.unnamed_statement = Some(stmt(7));
        let portal = |name: &str, clock: u64| Portal {
            statement_name: name.to_string(),
            statement: stmt(clock),
            params: vec![],
            result_formats: vec![],
            cached: None,
            rows_sent: 0,
            txn_at_bind: None,
            gen_at_bind: 0,
            sp_clock: clock,
        };
        state.portals.insert("p_old".to_string(), portal("old", 2));
        state.portals.insert("p_new".to_string(), portal("new", 6));
        state.unnamed_portal = Some(portal("old", 8));
        // Roll back to the savepoint with clock 3: clocks > 3 go.
        state.close_after_savepoint(3);
        assert!(state.statements.contains_key("old"));
        assert!(!state.statements.contains_key("new"));
        assert!(
            state.unnamed_statement.is_none(),
            "unnamed statement (clock 7) must close"
        );
        assert!(state.portals.contains_key("p_old"));
        assert!(!state.portals.contains_key("p_new"));
        assert!(
            state.unnamed_portal.is_none(),
            "unnamed portal (clock 8) must close"
        );
    }

    #[test]
    fn scan_params_counts_highest_placeholder() {
        assert_eq!(
            scan_params(&toks("SELECT * FROM t WHERE a = $1")).unwrap(),
            1
        );
        assert_eq!(
            scan_params(&toks("INSERT INTO t VALUES ($2, $1)")).unwrap(),
            2
        );
        assert_eq!(scan_params(&toks("SELECT * FROM t")).unwrap(), 0);
    }

    #[test]
    fn scan_params_ignores_placeholders_in_strings_and_idents() {
        // '$1' inside a string literal and "$2" as a quoted
        // identifier are text, not parameters.
        assert_eq!(
            scan_params(&toks("SELECT * FROM t WHERE a = '$1' AND \"$2\" = 'x'")).unwrap(),
            0
        );
    }

    #[test]
    fn scan_params_rejects_gaps_and_zero() {
        let err = scan_params(&toks("SELECT * FROM t WHERE a = $1 AND b = $3")).unwrap_err();
        assert_eq!(err.code, "42P18");
        let err = scan_params(&toks("SELECT * FROM t WHERE a = $0")).unwrap_err();
        assert_eq!(err.code, "42601");
        let err = scan_params(&toks("SELECT * FROM t WHERE a = $1x")).unwrap_err();
        assert_eq!(err.code, "42601");
    }

    #[test]
    fn scan_params_caps_at_32767() {
        // A ParameterDescription count is an Int16: 32768
        // parameters would wrap negative on the wire, so Parse
        // rejects anything above 32767 with 54000. All of
        // $1..=$32767 present is fine; a lone $32768 is already
        // over the cap (checked before the gap check).
        let all: String = (1..=32767)
            .map(|i| format!("${i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT * FROM t WHERE a IN ({all})");
        assert_eq!(scan_params(&toks(&sql)).unwrap(), 32767);
        let err = scan_params(&toks("SELECT * FROM t WHERE a = $32768")).unwrap_err();
        assert_eq!(err.code, "54000");
        let err = scan_params(&toks("SELECT * FROM t WHERE a = $40000")).unwrap_err();
        assert_eq!(err.code, "54000");
    }

    #[test]
    fn substitute_replaces_placeholders_at_token_level() {
        let tokens = toks("SELECT * FROM t WHERE city = $1 AND id = $2");
        let out = substitute(
            &tokens,
            &["New'; DROP TABLE t; --".to_string(), "7".to_string()],
        );
        // The hostile value stays ONE token — it is never re-parsed.
        let city = out.iter().find(|t| t.text.starts_with("New")).unwrap();
        assert!(city.quoted_string);
        assert_eq!(city.text, "New'; DROP TABLE t; --");
        // And a '$1' inside a string literal is untouched.
        let tokens = toks("SELECT '$1' FROM t WHERE a = $1");
        let out = substitute(&tokens, &["v".to_string()]);
        assert_eq!(out[1].text, "$1"); // the literal
        assert!(out.iter().any(|t| t.text == "v"));
    }

    #[test]
    fn expand_codes_rules() {
        assert_eq!(expand_codes(&[], 3, "parameter").unwrap(), vec![0, 0, 0]);
        assert_eq!(expand_codes(&[1], 2, "parameter").unwrap(), vec![1, 1]);
        assert_eq!(expand_codes(&[0, 1], 2, "result").unwrap(), vec![0, 1]);
        assert_eq!(expand_codes(&[1], 0, "result").unwrap(), Vec::<i16>::new());
        let err = expand_codes(&[0, 1], 3, "result").unwrap_err();
        assert_eq!(err.code, "08P01");
        let err = expand_codes(&[2], 1, "parameter").unwrap_err();
        assert_eq!(err.code, "08P01");
    }

    #[test]
    fn decode_param_text_and_binary_int4() {
        // Text int4.
        assert_eq!(
            decode_param(&Some(b"42".to_vec()), OID_INT4, 0).unwrap(),
            "42"
        );
        // Binary int4: 4 bytes big-endian.
        assert_eq!(
            decode_param(&Some(42i32.to_be_bytes().to_vec()), OID_INT4, 1).unwrap(),
            "42"
        );
        // Negative binary int4.
        assert_eq!(
            decode_param(&Some((-7i32).to_be_bytes().to_vec()), OID_INT4, 1).unwrap(),
            "-7"
        );
        // Bad text int4.
        let err = decode_param(&Some(b"abc".to_vec()), OID_INT4, 0).unwrap_err();
        assert_eq!(err.code, "22P02");
        // Short binary int4.
        let err = decode_param(&Some(vec![0, 0]), OID_INT4, 1).unwrap_err();
        assert_eq!(err.code, "22P03");
        // NULL becomes the empty string.
        assert_eq!(decode_param(&None, OID_TEXT, 0).unwrap(), "");
        // Binary text is the raw bytes.
        assert_eq!(
            decode_param(&Some("héllo".as_bytes().to_vec()), OID_TEXT, 1).unwrap(),
            "héllo"
        );
    }

    #[test]
    fn msg_reader_rejects_truncation_and_trailing_bytes() {
        let mut r = MsgReader::new(&[0x00, 0x01]);
        assert_eq!(r.read_i16().unwrap(), 1);
        assert!(r.read_byte().is_err());
        let mut r = MsgReader::new(b"ab\0EXTRA");
        assert_eq!(r.read_cstr().unwrap(), "ab");
        assert!(r.at_end().is_err());
        let mut r = MsgReader::new(b"no-nul-here");
        assert!(r.read_cstr().is_err());
    }
}
