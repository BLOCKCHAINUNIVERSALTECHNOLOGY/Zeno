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
//
// Default data directory: ./zeno-data

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeno::doc;
use zeno::engine::Engine;
use zeno::table::TableStore;

const VERSION: &str = "0.1.0";

fn usage() -> String {
    format!(
        "Zeno {VERSION} — One Engine, All Data (V0.1 prototype)\n\
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
        JSON document (find is a linear scan in V0.1):\n\
        \x20 doc put <collection> <id> <json>\n\
        \x20 doc get <collection> <id>\n\
        \x20 doc find <collection> <field>=<value>\n\
        \n\
        Maintenance:\n\
        \x20 flush                    force memtable flush to an SSTable\n\
        \x20 compact                  merge SSTables, drop old versions + tombstones\n\
        \x20 stats                    show engine stats"
    )
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut data_dir = PathBuf::from("zeno-data");
    let mut args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "--data" && i + 1 < argv.len() {
            data_dir = PathBuf::from(&argv[i + 1]);
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

    match run(&data_dir, &args) {
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

fn run(data_dir: &Path, args: &[String]) -> Result<(), String> {
    let cmd = args[0].as_str();
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
