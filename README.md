# Zeno — One Engine, All Data

**Zeno is a hybrid SQL + JSON database in Rust, not ZenoDB (time-series) and not ZenDB.**

> **DRAFT (V0.11) — repo root par push ke time ye file root `README.md` banegi.**
> Abhi ye `prototype/docs-draft/` me draft hai; root README ko haath nahi lagaya gaya hai.

Ek engine, sab data. Table bhi, Document (JSON) bhi, Key-Value bhi — alag-alag database lagane ki zaroorat nahi.

- **General purpose, open source** — koi bhi vyakti use kar sakega
- **License:** Apache-2.0
- **Language:** Rust — fast + safe, no garbage-collector rukawat
- **Status:** V0.11 prototype, kaam kar raha hai, single-node. **Not production-ready yet** — production hardening, independent security audit aur `psql` se real-client verification abhi baaki hai (dekho `prototype/docs/V1-READINESS.md`).

## Quick-start (chalakar dekho)

Runnable code `prototype/` folder me hai — root par koi `Cargo.toml` ya `src/` nahi hai:

```sh
cd prototype
cargo run -- --data ./zeno-data put mykey myvalue
cargo run -- --data ./zeno-data get mykey
cargo run -- --data ./zeno-data serve --port 5433   # PostgreSQL wire protocol, 127.0.0.1 par
```

Asli CLI (poora list: `cargo run -- --help`):

- Key-value: `put <key> <value>`, `get <key>`, `del <key>`
- Table: `table create <name> <col1,col2,...>`, `table insert`, `table select`
- JSON document: `doc put <collection> <id> <json>`, `doc get`, `doc find`
- Maintenance: `flush`, `compact`, `vacuum`, `stats`
- Server: `serve [--port <port>] [--tls] [--max-connections <n>]`
- Benchmark (sirf Zeno ka apna engine, koi comparison nahi): `bench`

> `zeno run` naam ki koi command **nahi** hai — purane design draft me thi, implement nahi hui.

## Ek line me idea

- **Table (SQL):** `CREATE TABLE`, `SELECT`, `JOIN` (INNER / LEFT), subqueries, GROUP BY + aggregates — pakke data ke liye
- **Document (JSON):** bina schema ke JSON daalo — profile, log, content ke liye
- **Key-Value:** chhota data turant nikalo — login, session, setting ke liye

Teeno ek hi engine me — lekin cross-model transactional rollback (ek fail ho to teeno wapas) **abhi implemented nahi hai**: SQL transactions snapshot isolation ke saath kaam karte hain, aur ek statement ke andar multi-row UPDATE/DELETE atomic hai.

## Kaise kaam karta hai (implemented, sach)

- **WAL pehle** — har write pehle WAL file me append + fsync hota hai, phir memtable me jaata hai; crash ke baad WAL replay hota hai
- **Memtable → SSTable** — flush par memtable SSTable file banti hai; compaction/vacuum ek manifest (`sst-manifest.json`) commit karke generations badalte hain, taaki crash ke baad purana/deleted data wapas na aaye
- **PostgreSQL protocol** — psql / libpq clients Simple + extended protocol, SCRAM-SHA-256 auth, TLS 1.2/1.3
- **Sachchi limit:** SSTables open par poori memory me load hote hain (koi disk-backed block/cache nahi — Phase 2 ka kaam); koi secondary index nahi (`doc find` linear scan hai); single node hi hai

## V1 scope — pehle chhota, pakka

1. Ek node par chalega
2. Table banao, SQL se nikalo
3. JSON document daalo, nikalo
4. Crash ke baad data safe rahe (process-crash recovery test hai; asli power-loss test abhi nahi)
5. Benchmark baseline (Zeno-only) — PostgreSQL / MongoDB se comparison **V1 ke baad**, jab woh install ho

V1 me nahi hoga: multi-node / distributed, cloud hosting, production guarantee, 2PC, READ COMMITTED / SERIALIZABLE, secondary indexes. Poori authoritative list — kaunsi cheez release blocker hai, kaunsi post-V1/excluded — `prototype/docs/V1-READINESS.md` me hai.

## Docs

- Design draft (Hindi, simple — **proposal/future, implemented prototype se alag jagah saaf likhi hai**): [docs/DESIGN.md](docs/DESIGN.md)
- Prototype README (asli haalat, poora detail): [prototype/README.md](prototype/README.md)
- V1 readiness checklist: [prototype/docs/V1-READINESS.md](prototype/docs/V1-READINESS.md)

## Sachchi limit

Koi database har kaam me No.1 nahi hota. Zeno ka vaada: **simple + fast + sab data ek jagah**.

Naam ka note: pehle se ZenoDB aur ZenDB hain — ye Zeno unse alag hai, Rust hybrid database hai.

## Funding ka rasta

Pehle log use karenge, phir GitHub Sponsors / grants / hosted cloud. Funding turant nahi aayegi.
