// parser.rs — a real SQL parser for Zeno (V0.7).
//
// V0.6 and earlier parsed SQL by string-matching over a flat token
// list (`pgwire::tokenize` + `expect_*` helpers): one `column=value`
// WHERE filter, one SET assignment, no ORDER BY / LIMIT, no column
// list in INSERT, and `VARCHAR(10)` in CREATE TABLE failed. This
// module replaces that with a proper lexer (tokens carry line and
// column) plus a recursive-descent parser that produces a small AST
// (`Stmt`). `pgwire.rs` executes the AST; the old tokenizer stays
// only for statement classification and for the extended protocol's
// `$n` parameter substitution (which works at the token level).
//
// Supported (see README for the full list):
// - SELECT: column list or `*`, WHERE with AND-joined conditions
//   (`=`, `!=`, `<>`, `<`, `>`, `<=`, `>=`), ORDER BY [ASC|DESC],
//   LIMIT, OFFSET.
// - INSERT: optional column list, multi-row VALUES.
// - UPDATE: several SET assignments, WHERE with AND.
// - DELETE: WHERE with AND.
// - CREATE TABLE: column types (with an optional `(n)` / `(n,m)`
//   size, ignored — every Zeno column is text), plus `IF NOT
//   EXISTS` and the common per-column constraints PRIMARY KEY,
//   NOT NULL, UNIQUE, DEFAULT <value> (parsed and ignored).
//
// NOT supported, with an explicit error (not a silent misparse):
// JOIN, subqueries, GROUP BY / HAVING, UNION, aggregate or scalar
// function calls (`COUNT(*)`, ...). Those fail with 0A000
// ("feature not supported") and a message naming the construct, so
// a client can tell "not supported" apart from "syntax error".
// A genuine syntax error fails with 42601 and carries the line and
// column where parsing stopped — never a crash, never a panic.

use std::fmt;

/// Comparison operators in a WHERE condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

/// One value in the AST: a literal (string, number, or bare word —
/// all stored as text, because every Zeno column is text) or a
/// `$n` parameter placeholder. Placeholders only survive in a
/// prepared statement that has not been bound yet (extended
/// Describe); by execution time `extended::substitute` has replaced
/// them with quoted-string tokens, so an executor that meets one
/// reports 42601 instead of silently storing "$1" as data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Param(usize),
}

impl Value {
    /// The literal text, or `None` for an unbound `$n`.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            Value::Param(_) => None,
        }
    }
}

/// One `column <op> value` condition. Conditions in a WHERE are
/// AND-joined (there is no OR in V0.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub column: String,
    pub op: CmpOp,
    pub value: Value,
}

/// One parsed statement. Transaction control (BEGIN / COMMIT /
/// ROLLBACK / SAVEPOINT / RELEASE / VACUUM) is NOT here — it is
/// still classified and executed from the old token list in
// `pgwire.rs`, because it needs no values, no WHERE, and no
/// column resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    Create {
        table: String,
        /// (column name, declared type or `None`). The type is
        /// kept for error messages only — every column is text.
        columns: Vec<(String, Option<String>)>,
    },
    Insert {
        table: String,
        /// `None` = values are in registry column order.
        columns: Option<Vec<String>>,
        rows: Vec<Vec<Value>>,
    },
    Select {
        /// `None` = `*` (all columns, registry order).
        columns: Option<Vec<String>>,
        table: String,
        conditions: Vec<Condition>,
        /// ORDER BY keys in order: (column, true = ASC,
        /// false = DESC). Empty = no ORDER BY. M5 (V0.7
        /// review): several keys, e.g. `ORDER BY a, b DESC`.
        order_by: Vec<(String, bool)>,
        limit: Option<u64>,
        offset: Option<u64>,
    },
    Update {
        table: String,
        sets: Vec<(String, Value)>,
        conditions: Vec<Condition>,
    },
    Delete {
        table: String,
        conditions: Vec<Condition>,
    },
}

/// A parse failure: a PostgreSQL SQLSTATE code (`42601` syntax
/// error, `0A000` feature not supported), the 1-based line and
/// column where parsing stopped, and a plain message. `pgwire.rs`
/// turns this into an ErrorResponse whose message reads
/// `syntax error at line L, column C: ...`, so a client sees
/// exactly where the statement went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub code: &'static str,
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl ParseError {
    fn syntax(line: usize, col: usize, message: impl Into<String>) -> Self {
        Self {
            code: "42601",
            line,
            col,
            message: message.into(),
        }
    }

    fn unsupported(line: usize, col: usize, message: impl Into<String>) -> Self {
        Self {
            code: "0A000",
            line,
            col,
            message: message.into(),
        }
    }

    /// The message as sent to the client (code is separate, in the
    /// ErrorResponse's `C` field). A 0A000 is a feature the
    /// parser knows but Zeno does not support — it is NOT a syntax
    /// error, so it says so instead of "syntax error".
    pub fn to_sql_message(&self) -> String {
        if self.code == "0A000" {
            format!(
                "feature not supported at line {}, column {}: {}",
                self.line, self.col, self.message
            )
        } else {
            format!(
                "syntax error at line {}, column {}: {}",
                self.line, self.col, self.message
            )
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.to_sql_message())
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------

/// One lexed token, with its 1-based line/column (character-based,
/// so a multi-byte character counts once, like PostgreSQL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexToken {
    pub kind: TokKind,
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokKind {
    /// A bare word (`SELECT`, `users`) or a `"double-quoted"`
    /// identifier (same representation — quoting only matters to
    /// the lexer, which must not treat a `$1` or `;` inside the
    /// quotes as syntax).
    Ident(String),
    /// A `'single-quoted'` string literal (`''` = escaped quote).
    Str(String),
    /// A number literal, as written (`42`, `3.5`, `-7`).
    Num(String),
    /// A `$n` parameter placeholder.
    Param(usize),
    /// Punctuation: `(`, `)`, `,`, `;`, `*`, `.`, `=`, `!=`,
    /// `<>`, `<`, `>`, `<=`, `>=`.
    Punct(String),
}

impl LexToken {
    /// The token's text, for error messages and EOF positions.
    fn text(&self) -> String {
        match &self.kind {
            TokKind::Ident(s) | TokKind::Str(s) | TokKind::Num(s) | TokKind::Punct(s) => s.clone(),
            TokKind::Param(n) => format!("${n}"),
        }
    }

    /// Uppercase form of a bare word, or `""` for anything else.
    fn word_upper(&self) -> String {
        match &self.kind {
            TokKind::Ident(s) => s.to_ascii_uppercase(),
            _ => String::new(),
        }
    }

    fn is_word(&self, kw: &str) -> bool {
        matches!(&self.kind, TokKind::Ident(s) if s.eq_ignore_ascii_case(kw))
    }

    fn is_punct(&self, p: &str) -> bool {
        matches!(&self.kind, TokKind::Punct(s) if s == p)
    }
}

/// Lex `sql` into tokens. `--` line comments and `/* */` block
/// comments are skipped (a `;` or `$1` inside one is not syntax);
/// an unterminated string or block comment, or a stray character,
/// is a 42601 at the exact position.
pub fn lex(sql: &str) -> Result<Vec<LexToken>, ParseError> {
    let chars: Vec<char> = sql.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    // Advance one character, tracking line/column.
    let advance = |i: &mut usize, line: &mut usize, col: &mut usize| {
        if chars[*i] == '\n' {
            *line += 1;
            *col = 1;
        } else {
            *col += 1;
        }
        *i += 1;
    };

    while i < chars.len() {
        let c = chars[i];
        let (tok_line, tok_col) = (line, col);
        match c {
            ' ' | '\t' | '\r' | '\n' => advance(&mut i, &mut line, &mut col),
            '-' if chars.get(i + 1) == Some(&'-') => {
                // `--` line comment: skip to (not past) the newline.
                while i < chars.len() && chars[i] != '\n' {
                    advance(&mut i, &mut line, &mut col);
                }
            }
            '-' if chars.get(i + 1).is_some_and(|d| d.is_ascii_digit()) => {
                // A negative number literal (`-7`). There is no
                // arithmetic in V0.7, so `-` before a digit can
                // only be a sign, never subtraction.
                let mut s = String::from("-");
                advance(&mut i, &mut line, &mut col);
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    s.push(chars[i]);
                    advance(&mut i, &mut line, &mut col);
                }
                tokens.push(LexToken {
                    kind: TokKind::Num(s),
                    line: tok_line,
                    col: tok_col,
                });
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                // `/* */` block comment (not nested, like
                // PostgreSQL: the first `*/` ends it).
                let (start_line, start_col) = (tok_line, tok_col);
                advance(&mut i, &mut line, &mut col);
                advance(&mut i, &mut line, &mut col);
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        advance(&mut i, &mut line, &mut col);
                        advance(&mut i, &mut line, &mut col);
                        closed = true;
                        break;
                    }
                    advance(&mut i, &mut line, &mut col);
                }
                if !closed {
                    return Err(ParseError::syntax(
                        start_line,
                        start_col,
                        "unterminated block comment",
                    ));
                }
            }
            '\'' => {
                let mut s = String::new();
                advance(&mut i, &mut line, &mut col);
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == '\'' {
                        if chars.get(i + 1) == Some(&'\'') {
                            s.push('\'');
                            advance(&mut i, &mut line, &mut col);
                            advance(&mut i, &mut line, &mut col);
                        } else {
                            advance(&mut i, &mut line, &mut col);
                            closed = true;
                            break;
                        }
                    } else {
                        s.push(chars[i]);
                        advance(&mut i, &mut line, &mut col);
                    }
                }
                if !closed {
                    return Err(ParseError::syntax(
                        tok_line,
                        tok_col,
                        "unterminated string literal",
                    ));
                }
                tokens.push(LexToken {
                    kind: TokKind::Str(s),
                    line: tok_line,
                    col: tok_col,
                });
            }
            '"' => {
                let mut s = String::new();
                advance(&mut i, &mut line, &mut col);
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == '"' {
                        if chars.get(i + 1) == Some(&'"') {
                            s.push('"');
                            advance(&mut i, &mut line, &mut col);
                            advance(&mut i, &mut line, &mut col);
                        } else {
                            advance(&mut i, &mut line, &mut col);
                            closed = true;
                            break;
                        }
                    } else {
                        s.push(chars[i]);
                        advance(&mut i, &mut line, &mut col);
                    }
                }
                if !closed {
                    return Err(ParseError::syntax(
                        tok_line,
                        tok_col,
                        "unterminated quoted identifier",
                    ));
                }
                tokens.push(LexToken {
                    kind: TokKind::Ident(s),
                    line: tok_line,
                    col: tok_col,
                });
            }
            '(' | ')' | ',' | ';' | '*' | '.' => {
                advance(&mut i, &mut line, &mut col);
                tokens.push(LexToken {
                    kind: TokKind::Punct(c.to_string()),
                    line: tok_line,
                    col: tok_col,
                });
            }
            '=' | '<' | '>' | '!' => {
                // Two-character operators first: `<=`, `>=`,
                // `!=`, `<>`. A lone `!` is not an operator.
                let two: String = [c, chars.get(i + 1).copied().unwrap_or(' ')]
                    .iter()
                    .collect();
                if ["<=", ">=", "!=", "<>"].contains(&two.as_str()) {
                    advance(&mut i, &mut line, &mut col);
                    advance(&mut i, &mut line, &mut col);
                    tokens.push(LexToken {
                        kind: TokKind::Punct(two),
                        line: tok_line,
                        col: tok_col,
                    });
                } else if c == '!' {
                    return Err(ParseError::syntax(
                        tok_line,
                        tok_col,
                        "unexpected character '!' (did you mean '!='?)",
                    ));
                } else {
                    advance(&mut i, &mut line, &mut col);
                    tokens.push(LexToken {
                        kind: TokKind::Punct(c.to_string()),
                        line: tok_line,
                        col: tok_col,
                    });
                }
            }
            '$' => {
                advance(&mut i, &mut line, &mut col);
                let mut digits = String::new();
                while i < chars.len() && chars[i].is_ascii_digit() {
                    digits.push(chars[i]);
                    advance(&mut i, &mut line, &mut col);
                }
                if digits.is_empty() {
                    return Err(ParseError::syntax(
                        tok_line,
                        tok_col,
                        "invalid parameter placeholder '$' (expected '$' followed by a number, e.g. $1)",
                    ));
                }
                let n: usize = digits.parse().map_err(|_| {
                    ParseError::syntax(tok_line, tok_col, "parameter number is too large")
                })?;
                if n == 0 {
                    return Err(ParseError::syntax(
                        tok_line,
                        tok_col,
                        "there is no parameter $0",
                    ));
                }
                tokens.push(LexToken {
                    kind: TokKind::Param(n),
                    line: tok_line,
                    col: tok_col,
                });
            }
            _ if c.is_ascii_alphabetic() || c == '_' => {
                let mut s = String::new();
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '$')
                {
                    s.push(chars[i]);
                    advance(&mut i, &mut line, &mut col);
                }
                tokens.push(LexToken {
                    kind: TokKind::Ident(s),
                    line: tok_line,
                    col: tok_col,
                });
            }
            _ if c.is_ascii_digit() => {
                let mut s = String::new();
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    s.push(chars[i]);
                    advance(&mut i, &mut line, &mut col);
                }
                tokens.push(LexToken {
                    kind: TokKind::Num(s),
                    line: tok_line,
                    col: tok_col,
                });
            }
            _ => {
                return Err(ParseError::syntax(
                    tok_line,
                    tok_col,
                    format!("unexpected character '{c}'"),
                ));
            }
        }
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------
// Parser (recursive descent, one statement)
// ---------------------------------------------------------------------

/// Column types accepted in CREATE TABLE. The type is parsed and
/// then ignored (every Zeno column is text); the list exists so a
/// missing comma (`(id name)`) is a syntax error instead of
/// silently treating `name` as `id`'s type.
const KNOWN_TYPES: &[&str] = &[
    "INT",
    "INTEGER",
    "BIGINT",
    "SMALLINT",
    "TINYINT",
    "TEXT",
    "VARCHAR",
    "CHAR",
    "CHARACTER",
    "BOOLEAN",
    "BOOL",
    "REAL",
    "DOUBLE",
    "FLOAT",
    "NUMERIC",
    "DECIMAL",
    "SERIAL",
    "BIGSERIAL",
    "SMALLSERIAL",
    "TIMESTAMP",
    "DATE",
    "TIME",
    "UUID",
    "JSONB",
    "JSON",
    "BYTEA",
];

/// Aggregate / scalar function names: any of these followed by
/// `(` is a function call, which V0.7 does not support.
const FUNCTION_NAMES: &[&str] = &[
    "COUNT",
    "SUM",
    "AVG",
    "MIN",
    "MAX",
    "COALESCE",
    "NULLIF",
    "UPPER",
    "LOWER",
    "LENGTH",
    "NOW",
    "CURRENT_DATE",
];

/// Parse exactly one statement. A trailing `;` is allowed (Simple
/// Query splits on `;` first, so it rarely reaches here, but the
/// extended-protocol token reconstruction can leave one behind).
pub fn parse_sql(sql: &str) -> Result<Stmt, ParseError> {
    let tokens = lex(sql)?;
    let mut p = Parser::new(tokens);
    let stmt = p.parse_statement()?;
    // A single trailing semicolon is fine; anything else is not.
    if let Some(t) = p.peek() {
        if t.is_punct(";") {
            p.next();
        }
    }
    if let Some(t) = p.peek() {
        return Err(p.unsupported_or_syntax(t));
    }
    Ok(stmt)
}

struct Parser {
    tokens: Vec<LexToken>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<LexToken>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&LexToken> {
        self.tokens.get(self.pos)
    }

    fn peek2(&self) -> Option<&LexToken> {
        self.tokens.get(self.pos + 1)
    }

    fn next(&mut self) -> Option<LexToken> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    /// Position for an "unexpected end of input" error: just past
    /// the last token (or 1,1 for an empty statement).
    fn eof_pos(&self) -> (usize, usize) {
        match self.tokens.last() {
            Some(t) => (t.line, t.col + t.text().chars().count()),
            None => (1, 1),
        }
    }

    fn err_eof(&self, what: &str) -> ParseError {
        let (line, col) = self.eof_pos();
        ParseError::syntax(
            line,
            col,
            format!("unexpected end of input — expected {what}"),
        )
    }

    fn err_at(&self, t: &LexToken, what: &str) -> ParseError {
        ParseError::syntax(
            t.line,
            t.col,
            format!("syntax error near '{}' — expected {what}", t.text()),
        )
    }

    /// The error for a trailing token after a complete statement:
    /// 0A000 when it starts a construct V0.7 knows but does not
    /// support (JOIN, GROUP BY, ...), 42601 otherwise.
    fn unsupported_or_syntax(&self, t: &LexToken) -> ParseError {
        match t.word_upper().as_str() {
            "JOIN" | "LEFT" | "RIGHT" | "INNER" | "FULL" | "CROSS" => ParseError::unsupported(
                t.line,
                t.col,
                "JOIN is not supported in Zeno 0.7.0 — query one table at a time \
                 (see README: what the parser does not support)",
            ),
            "GROUP" | "HAVING" => ParseError::unsupported(
                t.line,
                t.col,
                "GROUP BY / HAVING is not supported in Zeno 0.7.0 — no aggregates yet",
            ),
            "UNION" | "EXCEPT" | "INTERSECT" => ParseError::unsupported(
                t.line,
                t.col,
                format!(
                    "{} is not supported in Zeno 0.7.0 — one SELECT per statement",
                    t.word_upper()
                ),
            ),
            "ON" => ParseError::unsupported(
                t.line,
                t.col,
                "JOIN ... ON is not supported in Zeno 0.7.0 — query one table at a time",
            ),
            _ => ParseError::syntax(
                t.line,
                t.col,
                format!("unexpected '{}' after the statement", t.text()),
            ),
        }
    }

    /// Consume the keyword `kw` (case-insensitive) or fail.
    fn expect_word(&mut self, kw: &str) -> Result<LexToken, ParseError> {
        match self.peek() {
            Some(t) if t.is_word(kw) => Ok(self.next().expect("peeked token")),
            Some(t) => Err(self.err_at(t, &format!("'{kw}'"))),
            None => Err(self.err_eof(&format!("'{kw}'"))),
        }
    }

    /// Consume the keyword `kw` if present; returns whether it was there.
    fn eat_word(&mut self, kw: &str) -> bool {
        if self.peek().is_some_and(|t| t.is_word(kw)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consume the punctuation `p` or fail.
    fn expect_punct(&mut self, p: &str) -> Result<LexToken, ParseError> {
        match self.peek() {
            Some(t) if t.is_punct(p) => Ok(self.next().expect("peeked token")),
            Some(t) => Err(self.err_at(t, &format!("'{p}'"))),
            None => Err(self.err_eof(&format!("'{p}'"))),
        }
    }

    fn eat_punct(&mut self, p: &str) -> bool {
        if self.peek().is_some_and(|t| t.is_punct(p)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// A table/column name: any identifier (bare or "quoted").
    /// A keyword used as a name is allowed — this is a prototype
    /// subset, not full PostgreSQL.
    fn expect_name(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(t) => match &t.kind {
                TokKind::Ident(name) => {
                    let name = name.clone();
                    self.pos += 1;
                    Ok(name)
                }
                _ => Err(self.err_at(t, "a name")),
            },
            None => Err(self.err_eof("a name")),
        }
    }

    /// A value: string literal, number, `$n`, or a bare word
    /// (`Delhi`, `TRUE` — stored as that text, as before).
    /// `(` starts a subquery, which is not supported. A bare
    /// word followed by `(` is a function call (`upper('x')`,
    /// `now()`) — also not supported, and m1 (V0.7 review) it
    /// fails with 0A000, not 42601.
    fn parse_value(&mut self) -> Result<Value, ParseError> {
        if let Some(t) = self.peek().cloned() {
            if matches!(&t.kind, TokKind::Ident(_)) && self.peek2().is_some_and(|n| n.is_punct("("))
            {
                return Err(ParseError::unsupported(
                    t.line,
                    t.col,
                    format!(
                        "function call {}(...) is not supported in Zeno 0.7.0 — use a literal value",
                        t.word_upper()
                    ),
                ));
            }
        }
        match self.peek() {
            Some(t) => match &t.kind {
                TokKind::Str(s) | TokKind::Num(s) => {
                    let v = Value::Text(s.clone());
                    self.pos += 1;
                    Ok(v)
                }
                TokKind::Param(n) => {
                    let v = Value::Param(*n);
                    self.pos += 1;
                    Ok(v)
                }
                TokKind::Ident(s) => {
                    let v = Value::Text(s.clone());
                    self.pos += 1;
                    Ok(v)
                }
                TokKind::Punct(p) if p == "(" => Err(ParseError::unsupported(
                    t.line,
                    t.col,
                    "subqueries are not supported in Zeno 0.7.0 — use a literal value",
                )),
                _ => Err(self.err_at(t, "a value")),
            },
            None => Err(self.err_eof("a value")),
        }
    }

    fn parse_statement(&mut self) -> Result<Stmt, ParseError> {
        let first = match self.peek() {
            Some(t) => t.clone(),
            None => return Err(ParseError::syntax(1, 1, "empty statement")),
        };
        match first.word_upper().as_str() {
            "SELECT" => self.parse_select(),
            "INSERT" => self.parse_insert(),
            "UPDATE" => self.parse_update(),
            "DELETE" => self.parse_delete(),
            "CREATE" => self.parse_create(),
            "WITH" => Err(ParseError::unsupported(
                first.line,
                first.col,
                "WITH (common table expressions) is not supported in Zeno 0.7.0",
            )),
            other => Err(ParseError::syntax(
                first.line,
                first.col,
                format!(
                    "unsupported statement starting with '{other}' — only SELECT, INSERT, \
                     UPDATE, DELETE and CREATE TABLE are parsed here"
                ),
            )),
        }
    }

    fn parse_select(&mut self) -> Result<Stmt, ParseError> {
        self.expect_word("SELECT")?;
        // Column list: `*` or comma-separated names. A function
        // call (`COUNT(*)`) is not supported, not a column.
        let columns: Option<Vec<String>> = if self.eat_punct("*") {
            None
        } else {
            let mut cols = Vec::new();
            loop {
                let t = self
                    .peek()
                    .cloned()
                    .ok_or_else(|| self.err_eof("a column name"))?;
                if let TokKind::Ident(name) = &t.kind {
                    let upper = name.to_ascii_uppercase();
                    if FUNCTION_NAMES.contains(&upper.as_str())
                        && self.peek2().is_some_and(|n| n.is_punct("("))
                    {
                        return Err(ParseError::unsupported(
                            t.line,
                            t.col,
                            format!(
                                "aggregate/function {upper}(...) is not supported in Zeno 0.7.0 \
                                 — no aggregates yet (see README)"
                            ),
                        ));
                    }
                    if self.peek2().is_some_and(|n| n.is_punct("(")) {
                        return Err(ParseError::unsupported(
                            t.line,
                            t.col,
                            format!("function call {upper}(...) is not supported in Zeno 0.7.0"),
                        ));
                    }
                }
                cols.push(self.expect_name()?);
                if self.eat_punct(",") {
                    continue;
                }
                break;
            }
            Some(cols)
        };
        self.expect_word("FROM")?;
        // `FROM (` is a subquery, not a table.
        if self.peek().is_some_and(|t| t.is_punct("(")) {
            let t = self.peek().expect("peeked token").clone();
            return Err(ParseError::unsupported(
                t.line,
                t.col,
                "subqueries are not supported in Zeno 0.7.0 — query a table directly",
            ));
        }
        let table = self.expect_name()?;
        let conditions = self.parse_where_opt()?;
        // M5 (V0.7 review): ORDER BY takes a comma-separated
        // list of keys, each with its own ASC/DESC.
        let mut order_by: Vec<(String, bool)> = Vec::new();
        if self.eat_word("ORDER") {
            self.expect_word("BY")?;
            loop {
                let col = self.expect_name()?;
                let asc = if self.eat_word("DESC") {
                    false
                } else {
                    // ASC is the default; consume it if present.
                    self.eat_word("ASC");
                    true
                };
                order_by.push((col, asc));
                if self.eat_punct(",") {
                    continue;
                }
                break;
            }
        }
        // M5 (V0.7 review): LIMIT and OFFSET in either order —
        // `OFFSET 0 LIMIT 1` is as valid as `LIMIT 1 OFFSET 0`.
        // A repeated LIMIT (or OFFSET) is still a syntax error.
        let mut limit: Option<u64> = None;
        let mut offset: Option<u64> = None;
        loop {
            if self.peek().is_some_and(|t| t.is_word("LIMIT")) {
                let t = self.next().expect("peeked token");
                if limit.is_some() {
                    return Err(ParseError::syntax(
                        t.line,
                        t.col,
                        "LIMIT given twice in one SELECT",
                    ));
                }
                limit = Some(self.parse_non_negative_int("LIMIT")?);
            } else if self.peek().is_some_and(|t| t.is_word("OFFSET")) {
                let t = self.next().expect("peeked token");
                if offset.is_some() {
                    return Err(ParseError::syntax(
                        t.line,
                        t.col,
                        "OFFSET given twice in one SELECT",
                    ));
                }
                offset = Some(self.parse_non_negative_int("OFFSET")?);
            } else {
                break;
            }
        }
        Ok(Stmt::Select {
            columns,
            table,
            conditions,
            order_by,
            limit,
            offset,
        })
    }

    /// `[WHERE cond AND cond ...]` — empty when no WHERE.
    fn parse_where_opt(&mut self) -> Result<Vec<Condition>, ParseError> {
        if !self.eat_word("WHERE") {
            return Ok(Vec::new());
        }
        let mut conditions = vec![self.parse_condition()?];
        while self.eat_word("AND") {
            conditions.push(self.parse_condition()?);
        }
        // OR is not supported in V0.7: say so, instead of
        // silently treating it as AND.
        if let Some(t) = self.peek() {
            if t.is_word("OR") {
                return Err(ParseError::unsupported(
                    t.line,
                    t.col,
                    "OR in WHERE is not supported in Zeno 0.7.0 — use AND, or run two queries",
                ));
            }
        }
        Ok(conditions)
    }

    fn parse_condition(&mut self) -> Result<Condition, ParseError> {
        let column = self.expect_name()?;
        // `IN (SELECT ...)` / `EXISTS (SELECT ...)`: the subquery
        // is the unsupported part — say so, instead of reporting
        // the `IN` as a bad comparison operator.
        if let Some(t) = self.peek().cloned() {
            if (t.is_word("IN") || t.is_word("EXISTS"))
                && self.peek2().is_some_and(|n| n.is_punct("("))
            {
                return Err(ParseError::unsupported(
                    t.line,
                    t.col,
                    format!(
                        "subqueries ({} (SELECT ...)) are not supported in Zeno 0.7.0 — \
                         use a literal value, or run the inner query first",
                        t.word_upper()
                    ),
                ));
            }
        }
        let op_tok = self
            .next()
            .ok_or_else(|| self.err_eof("a comparison operator"))?;
        let op = match op_tok.kind {
            TokKind::Punct(ref p) => match p.as_str() {
                "=" => CmpOp::Eq,
                "!=" | "<>" => CmpOp::Ne,
                "<" => CmpOp::Lt,
                ">" => CmpOp::Gt,
                "<=" => CmpOp::Le,
                ">=" => CmpOp::Ge,
                _ => {
                    return Err(ParseError::syntax(
                        op_tok.line,
                        op_tok.col,
                        format!("expected a comparison operator (=, !=, <, >, <=, >=), got '{p}'"),
                    ));
                }
            },
            _ => {
                // m1 (V0.7 review): a KNOWN construct Zeno does
                // not support is 0A000 (feature not supported),
                // not 42601 (syntax error) — a client can tell
                // "not supported" apart from "bad syntax". That
                // covers LIKE / ILIKE, IS [NOT] NULL, NOT LIKE,
                // BETWEEN and an IN list.
                match op_tok.word_upper().as_str() {
                    "LIKE" | "ILIKE" => {
                        return Err(ParseError::unsupported(
                            op_tok.line,
                            op_tok.col,
                            "LIKE is not supported in Zeno 0.7.0 — no pattern matching yet (see README)",
                        ));
                    }
                    "IS" => {
                        return Err(ParseError::unsupported(
                            op_tok.line,
                            op_tok.col,
                            "IS [NOT] NULL is not supported in Zeno 0.7.0 — Zeno has no NULLs (see README)",
                        ));
                    }
                    "NOT" | "BETWEEN" | "IN" => {
                        return Err(ParseError::unsupported(
                            op_tok.line,
                            op_tok.col,
                            format!(
                                "{} is not supported in Zeno 0.7.0 — use a plain comparison operator (=, !=, <, >, <=, >=)",
                                op_tok.word_upper()
                            ),
                        ));
                    }
                    _ => {
                        return Err(ParseError::syntax(
                            op_tok.line,
                            op_tok.col,
                            format!(
                                "expected a comparison operator (=, !=, <, >, <=, >=), got '{}'",
                                op_tok.text()
                            ),
                        ));
                    }
                }
            }
        };
        let value = self.parse_value()?;
        Ok(Condition { column, op, value })
    }

    /// A non-negative integer literal after LIMIT / OFFSET.
    fn parse_non_negative_int(&mut self, what: &str) -> Result<u64, ParseError> {
        let t = self.next().ok_or_else(|| self.err_eof("a number"))?;
        match &t.kind {
            TokKind::Num(s) => s.parse::<u64>().map_err(|_| {
                ParseError::syntax(
                    t.line,
                    t.col,
                    format!("{what} must be a non-negative integer, got '{s}'"),
                )
            }),
            TokKind::Param(_) => Err(ParseError::syntax(
                t.line,
                t.col,
                format!(
                    "{what} with a parameter is not supported in Zeno 0.7.0 — use a literal number"
                ),
            )),
            _ => Err(ParseError::syntax(
                t.line,
                t.col,
                format!("{what} must be a non-negative integer, got '{}'", t.text()),
            )),
        }
    }

    fn parse_insert(&mut self) -> Result<Stmt, ParseError> {
        self.expect_word("INSERT")?;
        self.expect_word("INTO")?;
        let table = self.expect_name()?;
        // Optional column list: `INSERT INTO t (a, b) VALUES ...`.
        let mut columns: Option<Vec<String>> = None;
        if self.eat_punct("(") {
            let mut cols = Vec::new();
            loop {
                cols.push(self.expect_name()?);
                if self.eat_punct(",") {
                    continue;
                }
                break;
            }
            self.expect_punct(")")?;
            columns = Some(cols);
        }
        // m1 (V0.7 review): INSERT ... SELECT is a known
        // construct Zeno does not support — 0A000, not 42601.
        if let Some(t) = self.peek().cloned() {
            if t.is_word("SELECT") {
                return Err(ParseError::unsupported(
                    t.line,
                    t.col,
                    "INSERT ... SELECT is not supported in Zeno 0.7.0 — run the SELECT first, then INSERT the values",
                ));
            }
        }
        self.expect_word("VALUES")?;
        let mut rows: Vec<Vec<Value>> = Vec::new();
        loop {
            self.expect_punct("(")?;
            let mut row = Vec::new();
            // An empty `()` is a syntax error, not an empty row.
            if self.peek().is_some_and(|t| t.is_punct(")")) {
                let t = self.peek().expect("peeked token").clone();
                return Err(ParseError::syntax(
                    t.line,
                    t.col,
                    "VALUES (...) needs at least one value",
                ));
            }
            loop {
                row.push(self.parse_value()?);
                if self.eat_punct(",") {
                    continue;
                }
                break;
            }
            self.expect_punct(")")?;
            if let Some(cols) = &columns {
                if row.len() != cols.len() {
                    let t = self.tokens.get(self.pos.saturating_sub(1)).cloned();
                    let (line, col) = t.map(|t| (t.line, t.col)).unwrap_or((1, 1));
                    return Err(ParseError::syntax(
                        line,
                        col,
                        format!(
                            "INSERT row has {} values but the column list has {} columns",
                            row.len(),
                            cols.len()
                        ),
                    ));
                }
            }
            rows.push(row);
            if self.eat_punct(",") {
                continue;
            }
            break;
        }
        Ok(Stmt::Insert {
            table,
            columns,
            rows,
        })
    }

    fn parse_update(&mut self) -> Result<Stmt, ParseError> {
        self.expect_word("UPDATE")?;
        let table = self.expect_name()?;
        self.expect_word("SET")?;
        let mut sets = Vec::new();
        loop {
            let col = self.expect_name()?;
            self.expect_punct("=")?;
            let value = self.parse_value()?;
            sets.push((col, value));
            if self.eat_punct(",") {
                continue;
            }
            break;
        }
        let conditions = self.parse_where_opt()?;
        Ok(Stmt::Update {
            table,
            sets,
            conditions,
        })
    }

    fn parse_delete(&mut self) -> Result<Stmt, ParseError> {
        self.expect_word("DELETE")?;
        self.expect_word("FROM")?;
        let table = self.expect_name()?;
        let conditions = self.parse_where_opt()?;
        Ok(Stmt::Delete { table, conditions })
    }

    fn parse_create(&mut self) -> Result<Stmt, ParseError> {
        self.expect_word("CREATE")?;
        // Only CREATE TABLE exists in V0.7.
        if !self.eat_word("TABLE") {
            let t = self.peek().cloned().unwrap_or(LexToken {
                kind: TokKind::Ident(String::new()),
                line: 1,
                col: 1,
            });
            return Err(ParseError::unsupported(
                t.line,
                t.col,
                format!(
                    "only CREATE TABLE is supported in Zeno 0.7.0 (got CREATE '{}')",
                    t.text()
                ),
            ));
        }
        if self.eat_word("IF") {
            self.expect_word("NOT")?;
            self.expect_word("EXISTS")?;
        }
        let table = self.expect_name()?;
        self.expect_punct("(")?;
        let mut columns: Vec<(String, Option<String>)> = Vec::new();
        loop {
            // m1 (V0.7 review): a TABLE-level constraint
            // (PRIMARY KEY (...), UNIQUE (...), CHECK (...),
            // FOREIGN KEY (...), CONSTRAINT ...) is a known
            // construct Zeno does not support — 0A000, not
            // 42601. Per-column PRIMARY KEY / UNIQUE / NOT NULL
            // (parsed below) still work. The lookahead is
            // deliberately narrow (PRIMARY only before KEY, and
            // the rest only before `(`) so a column honestly
            // named e.g. `check` still parses.
            if let Some(t) = self.peek().cloned() {
                let table_constraint = match t.word_upper().as_str() {
                    "PRIMARY" => self.peek2().is_some_and(|n| n.is_word("KEY")),
                    "UNIQUE" | "CHECK" => self.peek2().is_some_and(|n| n.is_punct("(")),
                    "FOREIGN" => self.peek2().is_some_and(|n| n.is_word("KEY")),
                    "CONSTRAINT" => true,
                    _ => false,
                };
                if table_constraint {
                    return Err(ParseError::unsupported(
                        t.line,
                        t.col,
                        format!(
                            "table-level constraint {} is not supported in Zeno 0.7.0 — \
                             put PRIMARY KEY / UNIQUE on a single column instead",
                            t.word_upper()
                        ),
                    ));
                }
            }
            let name = self.expect_name()?;
            // Optional type, with an optional `(n)` / `(n,m)`
            // size — parsed, then ignored (every column is text).
            let mut ty: Option<String> = None;
            if let Some(t) = self.peek().cloned() {
                if let TokKind::Ident(word) = &t.kind {
                    let upper = word.to_ascii_uppercase();
                    if KNOWN_TYPES.contains(&upper.as_str()) {
                        ty = Some(upper);
                        self.pos += 1;
                        if self.eat_punct("(") {
                            // One or two integer sizes.
                            self.parse_non_negative_int("type size")?;
                            if self.eat_punct(",") {
                                self.parse_non_negative_int("type size")?;
                            }
                            self.expect_punct(")")?;
                        }
                    }
                }
            }
            // Per-column constraints, parsed and ignored:
            // PRIMARY KEY, NOT NULL, UNIQUE, DEFAULT <value>,
            // CHECK (...), REFERENCES <table> [(cols)].
            loop {
                if self.eat_word("PRIMARY") {
                    self.expect_word("KEY")?;
                } else if self.eat_word("NOT") {
                    self.expect_word("NULL")?;
                } else if self.eat_word("NULL") || self.eat_word("UNIQUE") {
                    // Consumed by the branch itself.
                } else if self.eat_word("DEFAULT") {
                    self.parse_value()?;
                } else if self.eat_word("CHECK") {
                    self.expect_punct("(")?;
                    self.skip_balanced_parens()?;
                } else if self.eat_word("REFERENCES") {
                    self.expect_name()?;
                    if self.eat_punct("(") {
                        loop {
                            self.expect_name()?;
                            if self.eat_punct(",") {
                                continue;
                            }
                            break;
                        }
                        self.expect_punct(")")?;
                    }
                } else {
                    break;
                }
            }
            columns.push((name, ty));
            if self.eat_punct(",") {
                continue;
            }
            break;
        }
        self.expect_punct(")")?;
        if columns.is_empty() {
            let (line, col) = self.eof_pos();
            return Err(ParseError::syntax(
                line,
                col,
                "a table needs at least one column",
            ));
        }
        Ok(Stmt::Create { table, columns })
    }

    /// After consuming a `(`, skip tokens until its matching `)`.
    /// Used for `CHECK (...)`, whose contents are not evaluated.
    fn skip_balanced_parens(&mut self) -> Result<(), ParseError> {
        let mut depth = 1usize;
        while let Some(t) = self.next() {
            if t.is_punct("(") {
                depth += 1;
            } else if t.is_punct(")") {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
        }
        Err(self.err_eof("')' to close the parenthesis"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(sql: &str) -> Stmt {
        parse_sql(sql).unwrap_or_else(|e| panic!("{sql:?} should parse: {e}"))
    }

    #[test]
    fn lexer_tracks_line_and_column() {
        let tokens = lex("SELECT *\nFROM users WHERE\n  city = 'Delhi'").unwrap();
        let city = tokens.iter().find(|t| t.text() == "city").unwrap();
        assert_eq!((city.line, city.col), (3, 3));
        let delhi = tokens.iter().find(|t| t.text() == "Delhi").unwrap();
        assert_eq!((delhi.line, delhi.col), (3, 10));
    }

    #[test]
    fn lexer_skips_comments_and_keeps_string_semicolons() {
        let tokens = lex("SELECT * FROM t /* ; $1 */ WHERE a = 'x;y' -- ; tail").unwrap();
        assert!(!tokens.iter().any(|t| t.text() == "$1"));
        assert!(tokens.iter().any(|t| t.text() == "x;y"));
    }

    #[test]
    fn lexer_reports_unterminated_string_with_position() {
        let err = lex("SELECT 'abc").unwrap_err();
        assert_eq!(err.code, "42601");
        assert_eq!((err.line, err.col), (1, 8));
    }

    #[test]
    fn select_star_with_multi_condition_where_order_limit_offset() {
        let stmt = parse(
            "SELECT * FROM users WHERE city = 'Delhi' AND id > 2 AND name != 'X' ORDER BY id DESC LIMIT 10 OFFSET 5",
        );
        match stmt {
            Stmt::Select {
                columns,
                table,
                conditions,
                order_by,
                limit,
                offset,
            } => {
                assert_eq!(columns, None);
                assert_eq!(table, "users");
                assert_eq!(conditions.len(), 3);
                assert_eq!(conditions[0].column, "city");
                assert_eq!(conditions[0].op, CmpOp::Eq);
                assert_eq!(conditions[1].op, CmpOp::Gt);
                assert_eq!(conditions[2].op, CmpOp::Ne);
                assert_eq!(order_by, vec![("id".to_string(), false)]);
                assert_eq!(limit, Some(10));
                assert_eq!(offset, Some(5));
            }
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn select_column_list_and_all_comparison_operators() {
        let stmt =
            parse("SELECT id, name FROM t WHERE a < 1 AND b <= 2 AND c >= 3 AND d <> 4 AND e = 5");
        match stmt {
            Stmt::Select {
                columns,
                conditions,
                ..
            } => {
                assert_eq!(columns, Some(vec!["id".to_string(), "name".to_string()]));
                assert_eq!(
                    conditions.iter().map(|c| &c.op).collect::<Vec<_>>(),
                    vec![&CmpOp::Lt, &CmpOp::Le, &CmpOp::Ge, &CmpOp::Ne, &CmpOp::Eq]
                );
            }
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn insert_column_list_and_multi_row_values() {
        let stmt =
            parse("INSERT INTO users (name, city) VALUES ('Sanjay', 'Delhi'), ('Asha', 'Mumbai')");
        match stmt {
            Stmt::Insert {
                table,
                columns,
                rows,
            } => {
                assert_eq!(table, "users");
                assert_eq!(columns, Some(vec!["name".to_string(), "city".to_string()]));
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0][0], Value::Text("Sanjay".to_string()));
            }
            other => panic!("expected Insert, got {other:?}"),
        }
    }

    #[test]
    fn update_multi_set_with_where_and() {
        let stmt =
            parse("UPDATE users SET city = 'Pune', name = 'Asha' WHERE id = 2 AND city = 'Mumbai'");
        match stmt {
            Stmt::Update {
                table,
                sets,
                conditions,
            } => {
                assert_eq!(table, "users");
                assert_eq!(sets.len(), 2);
                assert_eq!(sets[0].0, "city");
                assert_eq!(sets[1].0, "name");
                assert_eq!(conditions.len(), 2);
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn delete_with_multi_condition_where() {
        let stmt = parse("DELETE FROM users WHERE city = 'Delhi' AND id < 5");
        match stmt {
            Stmt::Delete { table, conditions } => {
                assert_eq!(table, "users");
                assert_eq!(conditions.len(), 2);
            }
            other => panic!("expected Delete, got {other:?}"),
        }
    }

    #[test]
    fn create_table_with_types_and_constraints() {
        let stmt = parse(
            "CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(10) NOT NULL, city TEXT, score NUMERIC(10, 2))",
        );
        match stmt {
            Stmt::Create { table, columns } => {
                assert_eq!(table, "users");
                assert_eq!(
                    columns.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
                    vec!["id", "name", "city", "score"]
                );
                assert_eq!(columns[1].1.as_deref(), Some("VARCHAR"));
            }
            other => panic!("expected Create, got {other:?}"),
        }
        // IF NOT EXISTS is accepted too.
        assert!(matches!(
            parse("CREATE TABLE IF NOT EXISTS t (id)"),
            Stmt::Create { .. }
        ));
    }

    #[test]
    fn syntax_error_carries_line_and_column() {
        let err = parse_sql("SELECT id FROM users\nWHERE city =").unwrap_err();
        assert_eq!(err.code, "42601");
        assert_eq!(err.line, 2, "error must point at line 2: {err}");
        assert!(err.to_sql_message().contains("line 2, column"));
        // A missing comma in the column list is a syntax error,
        // not a silently dropped column.
        let err = parse_sql("CREATE TABLE t (id name)").unwrap_err();
        assert_eq!(err.code, "42601");
    }

    #[test]
    fn join_group_by_aggregate_and_subquery_are_not_supported() {
        let err = parse_sql("SELECT * FROM a JOIN b ON a.id = b.id").unwrap_err();
        assert_eq!(err.code, "0A000");
        assert!(err.message.contains("JOIN"));
        let err = parse_sql("SELECT city, COUNT(*) FROM users GROUP BY city").unwrap_err();
        assert_eq!(err.code, "0A000");
        assert!(err.message.contains("COUNT"));
        let err = parse_sql("SELECT * FROM users WHERE id IN (SELECT id FROM t)").unwrap_err();
        assert_eq!(err.code, "0A000");
        assert!(err.message.to_lowercase().contains("subquer"));
        let err = parse_sql("SELECT * FROM users WHERE a = 1 OR b = 2").unwrap_err();
        assert_eq!(err.code, "0A000");
        assert!(err.message.contains("OR"));
    }

    #[test]
    fn select_multi_column_order_by_and_offset_before_limit() {
        // M5: several ORDER BY keys, and LIMIT/OFFSET in either
        // order — both parse to the same AST shape.
        let stmt = parse("SELECT * FROM t ORDER BY a, b DESC, c ASC OFFSET 0 LIMIT 1");
        match stmt {
            Stmt::Select {
                order_by,
                limit,
                offset,
                ..
            } => {
                assert_eq!(
                    order_by,
                    vec![
                        ("a".to_string(), true),
                        ("b".to_string(), false),
                        ("c".to_string(), true),
                    ]
                );
                assert_eq!(limit, Some(1));
                assert_eq!(offset, Some(0));
            }
            other => panic!("expected Select, got {other:?}"),
        }
        let stmt = parse("SELECT * FROM t LIMIT 1 OFFSET 0");
        match stmt {
            Stmt::Select { limit, offset, .. } => {
                assert_eq!(limit, Some(1));
                assert_eq!(offset, Some(0));
            }
            other => panic!("expected Select, got {other:?}"),
        }
        assert_eq!(
            parse_sql("SELECT * FROM t LIMIT 1 LIMIT 2")
                .unwrap_err()
                .code,
            "42601"
        );
        assert_eq!(
            parse_sql("SELECT * FROM t OFFSET 1 OFFSET 2")
                .unwrap_err()
                .code,
            "42601"
        );
    }

    #[test]
    fn unsupported_constructs_are_0a000_not_syntax_errors() {
        // m1: known-but-unsupported constructs fail with 0A000
        // (feature not supported), not 42601 (syntax error).
        for sql in [
            "SELECT * FROM t WHERE a LIKE '1%'",
            "SELECT * FROM t WHERE a IS NULL",
            "SELECT * FROM t WHERE a IS NOT NULL",
            "SELECT * FROM t WHERE a = upper('x')",
            "INSERT INTO t SELECT * FROM u",
            "CREATE TABLE t (id, PRIMARY KEY (id))",
            "CREATE TABLE t (id, UNIQUE (id))",
            "CREATE TABLE t (id, CHECK (id > 0))",
        ] {
            let err = parse_sql(sql).unwrap_err();
            assert_eq!(err.code, "0A000", "{sql}: {err}");
        }
    }

    #[test]
    fn limit_must_be_a_non_negative_integer() {
        let err = parse_sql("SELECT * FROM t LIMIT -1").unwrap_err();
        assert_eq!(err.code, "42601");
        let err = parse_sql("SELECT * FROM t LIMIT 'x'").unwrap_err();
        assert_eq!(err.code, "42601");
    }

    #[test]
    fn param_placeholder_survives_as_value() {
        // A prepared statement's `$1` parses (extended Describe
        // needs it); execution substitutes it before running.
        let stmt = parse("SELECT * FROM t WHERE city = $1");
        match stmt {
            Stmt::Select { conditions, .. } => {
                assert_eq!(conditions[0].value, Value::Param(1));
            }
            other => panic!("expected Select, got {other:?}"),
        }
    }
}
