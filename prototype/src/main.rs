// main.rs — the `zeno` command-line interface.
//
// Every subcommand opens the engine on a data directory, does one job,
// and exits. Because the WAL + SSTables live on disk, data survives
// across separate process runs — that is exactly what the demo proves
// by stopping and reopening.
//
// Usage:
//   zeno [--data <dir>] <command> [args]
//   zeno --data ./zeno-data put mykey myvalue
//   zeno --data ./zeno-data get mykey
//   zeno --data ./zeno-data del mykey
//   zeno --data ./zeno-data table create users id,name,city
//   zeno --data ./zeno-data table insert users 1,Sanjay,Delhi
//   zeno --data ./zeno-data table select users [city=Delhi]
//   zeno --data ./zeno-data table list
//   zeno --data ./zeno-data doc put profiles u1 '{"name":"Sanjay","city":"Delhi"}'
//   zeno --data ./zeno-data doc get profiles u1
//   zeno --data ./zeno-data doc find profiles city=Delhi
//   zeno --data ./zeno-data compact
//   zeno --data ./zeno-data flush
//   zeno --data ./zeno-data stats
//   zeno --data ./zeno-data hold 5   (diagnostic: hold the data-dir lock)
//
// Default data directory: ./zeno-data

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeno::doc;
use zeno::engine::Engine;
use zeno::table::TableStore;

const VERSION: &str = "0.9.0";

fn usage() -> String {
    format!(
        "Zeno {VERSION} — One Engine, All Data (V0.9 prototype)\n\
        \n\
        Usage: zeno [--data <dir>] <command> [args]   (default data dir: ./zeno-data)\n\
        \n\
        Key-Value:\n\
        \x20 put <key> <value>        store a value\n\
        \x20 get <key>                fetch a value\n\
        \x20 del <key>                delete a key (tombstone)\n\
        \n\
        Table (SQL over the wire protocol is parsed by the V0.8 parser;\n\
        \x20 the CLI below is still the simple one-command form):\n\
        \x20 table create <name> <col1,col2,...>\n\
        \x20 table insert <name> <val1,val2,...>\n\
        \x20 table select <name> [column=value]\n\
        \x20 table list\n\
        \n\
        JSON document (find is a linear scan in V0.5):\n\
        \x20 doc put <collection> <id> <json>\n\
        \x20 doc get <collection> <id>\n\
        \x20 doc find <collection> <field>=<value>\n\
        \n\
        Maintenance:\n\
        \x20 flush                    force memtable flush to an SSTable\n\
        \x20 compact                  merge SSTables, drop old versions + tombstones\n\
        \x20 vacuum                   online vacuum: prune old row versions + the\n\
        \x20                          committed-transaction set (safe while a server\n\
        \x20                          runs — use the VACUUM SQL statement there)\n\
        \x20 stats                    show engine stats\n\
        \x20 hold <seconds>           open the engine and hold its lock for N seconds\n\
        \x20                          (diagnostic for the lock demo / tests only)\n\
        \n\
        PostgreSQL wire protocol (V0.8, Simple + extended query, trust or SCRAM auth):\n\
        \x20 serve [--port <port>] [--tls] [--max-connections <n>]\n\
        \x20       [--vacuum-interval <seconds>] [--no-auto-vacuum]\n\
        \x20                          listen on 127.0.0.1:<port> (default 5432) and\n\
        \x20                          answer psql / libpq clients (prepared statements\n\
        \x20                          work now; MVCC transactions too: BEGIN /\n\
        \x20                          COMMIT / ROLLBACK, SAVEPOINT, UPDATE, snapshot\n\
        \x20                          isolation; real SQL parser: multi-condition\n\
        \x20                          WHERE, ORDER BY / LIMIT / OFFSET, multi-row\n\
        \x20                          INSERT, multi-SET UPDATE). A background\n\
        \x20                          auto-vacuum runs every --vacuum-interval\n\
        \x20                          seconds (default 60; --no-auto-vacuum turns\n\
        \x20                          it off) — it prunes only versions no live\n\
        \x20                          snapshot needs. On SIGINT/SIGTERM the server\n\
        \x20                          shuts down gracefully: it stops accepting new\n\
        \x20                          connections, lets live queries finish (up to 5s),\n\
        \x20                          stops the auto-vacuum, flushes the memtable and\n\
        \x20                          saves meta.json, then exits 0 (a second signal\n\
        \x20                          exits immediately).\n\
        \n\
        Benchmark (V0.8, Zeno's own engine only — no PostgreSQL/\n\
        \x20 MongoDB comparison: neither is installed here):\n\
        \x20 bench [--rows 100,1000,10000]\n\
        \x20                          measure KV put/get + table insert/select\n\
        \x20                          throughput and latency (median/p95) at each\n\
        \x20                          row count: 3 measured runs per row count,\n\
        \x20                          median of the 3 reported (a single sample\n\
        \x20                          varies run to run), with warmup, on a fresh\n\
        \x20                          temp dir (removed afterwards — your data is\n\
        \x20                          untouched).\n\
        \x20                          Numbers are for this machine only; see README.\n\
        \x20                          LOCAL PROTOTYPE ONLY: with no users\n\
        \x20                          configured any local client may connect, no\n\
        \x20                          password. Example: zeno --data ./my-data serve\n\
        \x20                          --port 5433\n\
        \x20                          --tls needs a certificate first: run\n\
        \x20                          `zeno cert generate` (self-signed, prototype\n\
        \x20                          only). --max-connections defaults to 20; past\n\
        \x20                          it a new connection gets ErrorResponse 53300.\n\
        \n\
        TLS certificate (self-signed — prototype only, see README):\n\
        \x20 cert generate            create server-cert.pem + server-key.pem\n\
        \x20                          (mode 0600) in the data dir for `serve --tls`.\n\
        \x20                          Refuses to overwrite an existing cert.\n\
        \n\
        Users (SCRAM-SHA-256 password auth for `serve`):\n\
        \x20 user set-password <name> set a password (asked twice on stdin;\n\
        \x20                          NOTE: it echoes as you type in this prototype —\n\
        \x20                          use a private terminal). The password is never\n\
        \x20                          stored; only its SCRAM verifier is kept. A\n\
        \x20                          server re-reads users on every new connection,\n\
        \x20                          so no restart is needed. 5 wrong logins lock\n\
        \x20                          a user@IP for 5 minutes (in-memory only).\n\
        \x20 user list                list users (empty = trust auth)\n\
        \x20 user remove <name>       remove a user (removing the last user\n\
        \x20                          switches new connections back to trust auth)"
    )
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut data_dir = PathBuf::from("zeno-data");
    let mut port: u16 = 5432;
    let mut tls = false;
    let mut max_connections: usize = zeno::pgwire::DEFAULT_MAX_CONNECTIONS;
    let mut vacuum_interval_secs: Option<u64> = Some(zeno::pgwire::DEFAULT_VACUUM_INTERVAL_SECS);
    let mut args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "--data" && i + 1 < argv.len() {
            data_dir = PathBuf::from(&argv[i + 1]);
            i += 2;
        } else if argv[i] == "--port" && i + 1 < argv.len() {
            match argv[i + 1].parse::<u16>() {
                Ok(p) => port = p,
                Err(_) => {
                    eprintln!(
                        "error: --port needs a number 0-65535, got '{}'",
                        argv[i + 1]
                    );
                    return ExitCode::FAILURE;
                }
            }
            i += 2;
        } else if argv[i] == "--tls" {
            tls = true;
            i += 1;
        } else if argv[i] == "--max-connections" && i + 1 < argv.len() {
            match argv[i + 1].parse::<usize>() {
                Ok(n) if n >= 1 => max_connections = n,
                _ => {
                    eprintln!(
                        "error: --max-connections needs a number >= 1, got '{}'",
                        argv[i + 1]
                    );
                    return ExitCode::FAILURE;
                }
            }
            i += 2;
        } else if argv[i] == "--vacuum-interval" && i + 1 < argv.len() {
            match argv[i + 1].parse::<u64>() {
                Ok(n) if n >= 1 => vacuum_interval_secs = Some(n),
                _ => {
                    eprintln!(
                        "error: --vacuum-interval needs a number >= 1 (seconds), got '{}'",
                        argv[i + 1]
                    );
                    return ExitCode::FAILURE;
                }
            }
            i += 2;
        } else if argv[i] == "--no-auto-vacuum" {
            vacuum_interval_secs = None;
            i += 1;
        } else {
            args.push(argv[i].clone());
            i += 1;
        }
    }

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    // M1 (V0.8 review): `--version` used to fall through to
    // `run()`, which opened the engine first — so `zeno --version`
    // in an empty directory exited 1 AND created a `zeno-data/`
    // directory (meta.json + wal.log). Like `--help`, it is handled
    // here, before any engine is opened.
    if args[0] == "--version" || args[0] == "-V" {
        println!("zeno {VERSION}");
        return ExitCode::SUCCESS;
    }

    match run(
        &data_dir,
        port,
        tls,
        max_connections,
        vacuum_interval_secs,
        &args,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn need(args: &[String], n: usize, what: &str) -> Result<(), String> {
    if args.len() < n {
        return Err(format!("missing {what} — see `zeno --help`"));
    }
    Ok(())
}

fn run(
    data_dir: &Path,
    port: u16,
    tls: bool,
    max_connections: usize,
    vacuum_interval_secs: Option<u64>,
    args: &[String],
) -> Result<(), String> {
    let cmd = args[0].as_str();

    // `serve` opens the engine itself (once, shared by all client
    // threads) and never returns until killed — it must not go through
    // the one-shot open below.
    if cmd == "serve" {
        let opts = zeno::pgwire::ServeOptions {
            tls,
            max_connections,
            vacuum_interval_secs,
        };
        return zeno::pgwire::serve(data_dir, port, &opts)
            .map_err(|e| format!("cannot serve on port {port}: {e}"));
    }

    // `cert` manages the TLS certificate files directly and must NOT
    // open the engine: generating a cert while a server runs is
    // fine (the server loads its cert once, at startup).
    if cmd == "cert" {
        return run_cert(data_dir, &args[1..]);
    }

    // `user` manages users.json directly and must NOT open the
    // engine: a running server holds the data-dir lock, and the
    // server re-reads users.json on every new connection anyway, so
    // a password set here applies at once, with no restart.
    if cmd == "user" {
        return run_user(data_dir, &args[1..]);
    }

    // `bench` measures the engine on a fresh TEMPORARY data
    // directory (deleted afterwards) — it must not open the user's
    // data dir, so it runs before the one-shot open below, like
    // `serve` / `cert` / `user`.
    if cmd == "bench" {
        return run_bench(&args[1..]);
    }

    // M1 (V0.8 review): validate the top-level command BEFORE
    // opening the engine. Any unknown command (a typo, `--version`
    // if it ever got this far) used to open the engine first and
    // create the data directory, then fail. The commands above
    // (`serve` / `cert` / `user` / `bench`) never open the engine;
    // the ones below all need it — so the check belongs here.
    const KNOWN_COMMANDS: &[&str] = &[
        "put", "get", "del", "flush", "compact", "vacuum", "hold", "stats", "table", "doc",
    ];
    if !KNOWN_COMMANDS.contains(&cmd) {
        return Err(format!("unknown command '{cmd}'\n\n{}", usage()));
    }

    let mut engine = Engine::open(data_dir).map_err(|e| format!("cannot open data dir: {e}"))?;
    let mut tables = TableStore::open(data_dir).map_err(|e| format!("cannot open tables: {e}"))?;

    match cmd {
        "put" => {
            need(args, 3, "key and value")?;
            engine.put(&args[1], &args[2]).map_err(|e| e.to_string())?;
            println!("OK  put {} = {}", args[1], args[2]);
        }
        "get" => {
            need(args, 2, "key")?;
            match engine.get(&args[1]) {
                Some(v) => println!("{} = {}", args[1], v),
                None => println!("{}: (not found)", args[1]),
            }
        }
        "del" => {
            need(args, 2, "key")?;
            engine.delete(&args[1]).map_err(|e| e.to_string())?;
            println!("OK  deleted {}", args[1]);
        }
        "flush" => {
            engine.flush().map_err(|e| e.to_string())?;
            println!("OK  memtable flushed to SSTable");
        }
        "compact" => {
            let count = engine.compact().map_err(|e| e.to_string())?;
            println!("OK  compacted — {count} SSTable(s) remain");
        }
        "vacuum" => {
            let report = engine.vacuum().map_err(|e| e.to_string())?;
            println!(
                "OK  vacuumed — {} old version(s) pruned, {} committed txn id(s) pruned, {} SSTable(s) remain",
                report.pruned_versions, report.committed_pruned, report.sstables
            );
        }
        "hold" => {
            // Diagnostic only (used by demo.sh and the lock tests):
            // open the engine — which takes the data-dir lock — and
            // keep the process alive for N seconds so a second process
            // can be shown failing to open the same directory. The
            // lock is released when this process exits (or is killed;
            // a killed holder leaves a stale lock that the next open
            // takes over once its PID is dead — see lock.rs).
            need(args, 2, "seconds to hold the lock")?;
            let secs: u64 = args[1]
                .parse()
                .map_err(|_| "hold needs a number of seconds".to_string())?;
            println!(
                "holding lock on {} for {secs}s (pid {}) — try another `zeno` command now",
                data_dir.display(),
                std::process::id()
            );
            std::thread::sleep(std::time::Duration::from_secs(secs));
            println!("done holding lock");
            // Keep `engine` alive until here so the lock is held the
            // whole time.
            let _ = engine.stats();
        }
        "stats" => {
            let s = engine.stats();
            println!("Zeno {VERSION} stats");
            println!("  memtable entries : {}", s.memtable_entries);
            println!(
                "  SSTables         : {} ({} entries)",
                s.sstable_count, s.sstable_entries
            );
            println!("  puts             : {}", s.puts);
            println!("  gets             : {}", s.gets);
            println!("  deletes          : {}", s.deletes);
            println!("  flushes          : {}", s.flushes);
            println!("  compactions      : {}", s.compactions);
            println!("  wal corrupt lines: {}", s.wal_corrupt_lines);
            if !s.wal_corrupt_line_numbers.is_empty() {
                println!(
                    "  wal corrupt line nos: {:?} (this open; count above is the lifetime total)",
                    s.wal_corrupt_line_numbers
                );
            }
            println!("  next SSTable id  : {}", s.next_sst_id);
            println!("  next txn id      : {}", s.next_txn_id);
            println!("  active txns      : {}", s.active_txns);
            println!("  committed txns   : {}", s.committed_txns);
            println!("  vacuums          : {}", s.vacuums);
            println!("  wal discarded txns: {}", s.wal_discarded_txns);
            println!("  tables           : {}", tables.list_tables().join(", "));
        }
        "table" => {
            need(args, 2, "table subcommand")?;
            match args[1].as_str() {
                "create" => {
                    need(args, 4, "table name and columns")?;
                    let columns: Vec<String> = args[3].split(',').map(str::to_string).collect();
                    tables.create_table(&args[2], columns)?;
                    println!("OK  table '{}' created", args[2]);
                }
                "insert" => {
                    need(args, 4, "table name and values")?;
                    let values: Vec<String> = args[3].split(',').map(str::to_string).collect();
                    let id = tables.insert(&mut engine, &args[2], values)?;
                    println!("OK  inserted row {} into '{}'", id, args[2]);
                }
                "select" => {
                    need(args, 3, "table name")?;
                    let filter = args.get(3).and_then(|f| f.split_once('='));
                    let rows = tables.select(&mut engine, &args[2], filter)?;
                    if rows.is_empty() {
                        println!("(no rows)");
                    } else {
                        for (id, row) in rows {
                            let parts: Vec<String> =
                                row.iter().map(|(k, v)| format!("{k}={v}")).collect();
                            println!("row {id}: {}", parts.join(", "));
                        }
                    }
                }
                "list" => {
                    let names = tables.list_tables();
                    if names.is_empty() {
                        println!("(no tables)");
                    } else {
                        for name in names {
                            println!("{name}");
                        }
                    }
                }
                other => return Err(format!("unknown table command '{other}'")),
            }
        }
        "doc" => {
            need(args, 2, "doc subcommand")?;
            match args[1].as_str() {
                "put" => {
                    need(args, 5, "collection, id and JSON")?;
                    doc::DocStore::put(&mut engine, &args[2], &args[3], &args[4])?;
                    println!("OK  doc {}/{} stored", args[2], args[3]);
                }
                "get" => {
                    need(args, 4, "collection and id")?;
                    match doc::DocStore::get(&mut engine, &args[2], &args[3]) {
                        Some(json) => println!("{json}"),
                        None => println!("{}/{}: (not found)", args[2], args[3]),
                    }
                }
                "find" => {
                    need(args, 4, "collection and field=value")?;
                    let Some((field, value)) = args[3].split_once('=') else {
                        return Err("doc find needs field=value".to_string());
                    };
                    let hits = doc::DocStore::find(&mut engine, &args[2], field, value);
                    if hits.is_empty() {
                        println!("(no documents match {field}={value})");
                    } else {
                        for (id, json) in hits {
                            println!("{id}: {json}");
                        }
                    }
                }
                other => return Err(format!("unknown doc command '{other}'")),
            }
        }
        other => return Err(format!("unknown command '{other}'\n\n{}", usage())),
    }
    Ok(())
}

/// `bench [--rows 100,1000,10000]`: measure Zeno's own engine
/// (see `bench.rs`). Runs on a fresh temp dir, never on `--data`.
fn run_bench(args: &[String]) -> Result<(), String> {
    let mut rows = zeno::bench::DEFAULT_ROWS.to_vec();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--rows" && i + 1 < args.len() {
            rows = zeno::bench::parse_rows(&args[i + 1])?;
            i += 2;
        } else {
            return Err(format!(
                "unknown bench argument '{}' — usage: zeno bench [--rows 100,1000,10000]",
                args[i]
            ));
        }
    }
    zeno::bench::run(&rows)
}

fn run_cert(data_dir: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "generate" => {
            zeno::tls::generate_cert(data_dir)?;
            println!(
                "OK  self-signed certificate created in {}",
                data_dir.display()
            );
            println!("    cert: {} (mode 0600)", zeno::tls::CERT_FILE);
            println!("    key:  {} (mode 0600)", zeno::tls::KEY_FILE);
            println!("    SANs: localhost, 127.0.0.1 — valid 1 year from now.");
            println!(
                "    WARNING: SELF-SIGNED — prototype only. Clients will not trust it unless they are told to (pin the cert / sslmode=require with this cert as trust root). Production needs a real CA certificate. Start the server with `zeno serve --tls`."
            );
            Ok(())
        }
        other => Err(format!(
            "unknown cert command '{other}' — see `zeno --help` (only `cert generate` exists)"
        )),
    }
}

/// Read a password line from stdin (the trailing newline is
/// stripped; any other whitespace is part of the password).
fn read_password_line(prompt: &str) -> Result<String, String> {
    use std::io::BufRead;
    print!("{prompt}");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read password: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn run_user(data_dir: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "set-password" => {
            let name = args.get(1).ok_or_else(|| {
                "usage: zeno user set-password <username> (password is asked on stdin)".to_string()
            })?;
            println!("setting password for user '{name}'");
            println!(
                "NOTE: the password echoes as you type in this prototype — use a private terminal."
            );
            let first = read_password_line("Password: ")?;
            let second = read_password_line("Repeat password: ")?;
            if first != second {
                return Err("passwords do not match — nothing was changed".to_string());
            }
            zeno::auth::set_password(data_dir, name, &first)?;
            println!("OK  password set for '{name}' — new connections now need SCRAM-SHA-256 auth");
            Ok(())
        }
        "list" => {
            let users = zeno::auth::list_users(data_dir)?;
            if users.is_empty() {
                println!("(no users — trust auth: any local client may connect, no password)");
            } else {
                for name in users {
                    println!("{name}");
                }
            }
            Ok(())
        }
        "remove" => {
            let name = args
                .get(1)
                .ok_or_else(|| "usage: zeno user remove <username>".to_string())?;
            if zeno::auth::remove_user(data_dir, name)? {
                println!("OK  user '{name}' removed");
                if zeno::auth::list_users(data_dir)?.is_empty() {
                    println!(
                        "WARNING: no users left — new connections are back to trust auth                          (any local client, no password)"
                    );
                }
            } else {
                println!("user '{name}' does not exist — nothing changed");
            }
            Ok(())
        }
        other => Err(format!(
            "unknown user command '{other}' — see `zeno --help` (set-password, list, remove)"
        )),
    }
}
