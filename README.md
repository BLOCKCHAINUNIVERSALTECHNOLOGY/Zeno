# Zeno — One Engine, All Data

**Zeno is a hybrid SQL + JSON database in Rust, not ZenoDB (time-series) and not ZenDB.**

Ek engine, sab data. Table bhi, Document (JSON) bhi, Key-Value bhi — alag-alag database lagane ki zaroorat nahi.

- **General purpose, open source** — koi bhi vyakti use kar sakega
- **License:** Apache-2.0
- **Language:** Rust — fast + safe, no garbage-collector rukawat
- **Status:** Early design, v0.1 in progress. Not production-ready yet.

## Ek line me idea

- **Table (SQL):** `CREATE TABLE`, `SELECT`, `JOIN` — pakke data ke liye
- **Document (JSON):** bina schema ke JSON daalo — profile, log, content ke liye
- **Fast (Key-Value + Cache):** chhota data turant nikalo — login, session, setting ke liye

Teeno ek hi transaction me — ek fail ho to sab wapas, data adha nahi rahega.

## Fast aur smooth kaise?

- B-Tree (padhne ke liye fast) + LSM (likhne ke liye fast)
- WAL pehle — light band hone par bhi data safe
- Memory cache — baar-baar manga data memory me
- PostgreSQL protocol — psql, DBeaver, Python, Node bina badle chalenge
- Ek command: `zeno run`

Target (lakshya, vaada nahi): chhote data par jawab millisecond me.

## V1 scope — pehle chhota, pakka

1. Ek node par chalega
2. Table banao, SQL se nikalo
3. JSON document daalo, nikalo
4. Crash ke baad data safe rahe
5. PostgreSQL aur MongoDB se benchmark compare

V1 me nahi hoga: multi-node / distributed, cloud hosting, production guarantee.

## Docs

- Design (Hindi, simple): [docs/DESIGN.md](docs/DESIGN.md)

## Sachchi limit

Koi database har kaam me No.1 nahi hota. Zeno ka vaada: **simple + fast + sab data ek jagah**.

Naam ka note: pehle se ZenoDB aur ZenDB hain — ye Zeno unse alag hai, Rust hybrid database hai.

## Funding ka rasta

Pehle log use karenge, phir GitHub Sponsors / grants / hosted cloud. Funding turant nahi aayegi.
