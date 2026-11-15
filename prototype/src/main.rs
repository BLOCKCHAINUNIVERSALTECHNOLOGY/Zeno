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

const VERSION: &str = "0.4.0";

fn usage() -> String {
    format!(
        "Zeno {VERSION} — One Engine, All Data (V0.4 prototype)\n\
        \n\
        Usage: zeno [--data <dir>] <command> [args]   (default data dir: ./zeno-data)\n\
        \n\
        Key-Value:\n\
        \x20 put <key> <value>        store a value\n\
        \x20 get <key>                fetch a value\n\
        \x20 del <key>                delete a key (tombstone)\n\
        \n\
        Table (no real SQL yet — SELECT is a simple scan filter):\n\
        \x20 table create <name> <col1,col2,...>\n\
        \x20 table insert <name> <val1,val2,...>\n\
        \x20 table select <name> [column=value]\n\
        \x20 table list\n\
        \n\
        JSON document (find is a linear scan in V0.4):\n\
        \x20 doc put <collection> <id> <json>\n\
        \x20 doc get <collection> <id>\n\
        \x20 doc find <collection> <field>=<value>\n\
        \n\
        Maintenance:\n\
        \x20 flush                    force memtable flush to an SSTable\n\
        \x20 compact                  merge SSTables, drop old versions + tombstones\n\
        \x20 stats                    show engine stats\n\
        \x20 hold <seconds>           open the engine and hold its lock for N seconds\n\
        \x20                          (diagnostic for the lock demo / tests only)\n\
        \n\
        PostgreSQL wire protocol (V0.4, Simple + extended query, trust or SCRAM auth):\n\
        \x20 serve [--port <port>]    listen on 127.0.0.1:<port> (default 5432) and\n\
        \x20                          answer psql / libpq clients (prepared statements\n\
        \x20                          work now). LOCAL PROTOTYPE ONLY: with no users\n\
        \x20                          configured any local client may connect, no\n\
        \x20                          password. Example: zeno --data ./my-data serve\n\
        \x20                          --port 5433\n\
        \n\
        Users (SCRAM-SHA-256 password auth for `serve`):\n\
        \x20 user set-password <name> set a password (asked twice on stdin;\n\
        \x20                          NOTE: it echoes as you type in this prototype —\n\
        \x20                          use a private terminal). The password is never\n\
        \x20                          stored; only its SCRAM verifier is kept. A\n\
        \x20                          server re-reads users on every new connection,\n\
        \x20                          so no restart is needed.\n\
        \x20 user list                list users (empty = trust auth)\n\
        \x20 user remove <name>       remove a user (removing the last user\n\
        \x20                          switches new connections back to trust auth)"
    )
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut data_dir = PathBuf::from("zeno-data");
    let mut port: u16 = 5432;
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
        } else {
            args.push(argv[i].clone());
            i += 1;
        }
    }

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    match run(&data_dir, port, &args) {
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

fn run(data_dir: &Path, port: u16, args: &[String]) -> Result<(), String> {
    let cmd = args[0].as_str();

    // `serve` opens the engine itself (once, shared by all client
    // threads) and never returns until killed — it must not go through
    // the one-shot open below.
    if cmd == "serve" {
        return zeno::pgwire::serve(data_dir, port)
            .map_err(|e| format!("cannot serve on port {port}: {e}"));
    }

    // `user` manages users.json directly and must NOT open the
    // engine: a running server holds the data-dir lock, and the
    // server re-reads users.json on every new connection anyway, so
    // a password set here applies at once, with no restart.
    if cmd == "user" {
        return run_user(data_dir, &args[1..]);
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
