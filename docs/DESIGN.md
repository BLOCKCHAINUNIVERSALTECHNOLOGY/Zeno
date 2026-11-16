# Zeno — Design Draft v0.2 (Hindi, simple)

> **DRAFT (V0.11) — repo root par push ke time ye file `docs/DESIGN.md` banegi.**
> Abhi ye `prototype/docs-draft/` me draft hai; root `docs/DESIGN.md` ko haath nahi lagaya gaya hai.
>
> **⚠️ YE DESIGN DRAFT HAI — PROPOSAL / FUTURE, IMPLEMENTED PROTOTYPE NAHI.**
> Neeche likhi cheezein Zeno ka **lakshya** hain, aaj ki haalat nahi. Aaj ka implemented
> prototype `prototype/` folder me hai aur uski asli haalat `prototype/README.md` aur
> `prototype/docs/V1-READINESS.md` me likhi hai. Jahan design aur implementation alag hain,
> woh har section ke neeche **"Aaj ki haalat (V0.11)"** me saaf likha hai — design ko
> capability ki tarah mat padho.

**Naam FINAL:** Zeno
**Risk note:** Pehle se ZenoDB (Lantern, Go time-series) aur ZenDB hain — Sanjay ne jaan kar risk le kar "Zeno hi rakho" chuna hai (2026-11-15). Isliye hamara Zeno alag pehchan se aayega: "Zeno — One Engine, All Data" tagline, Rust hybrid.
**Type:** General purpose, hybrid, open source database — koi bhi vyakti use kar sakega
**License:** Apache-2.0
**Language:** Rust (fast + safe)

## 1. Ek line me idea
Ek engine, sab data.
Table bhi, Document (JSON) bhi, Key-Value bhi, File bhi — alag-alag database lagane ki zaroorat nahi.

**Aaj ki haalat (V0.11):** Table (SQL), Document (JSON) aur Key-Value — teeno ek engine me implemented hain. File storage nahi hai.

## 2. Creative idea — "Ek Engine, Teen Chehre"
- **Table chehra (SQL):** `CREATE TABLE`, `SELECT`, `JOIN` — bank, shop, app ke pakke data ke liye
- **Document chehra (JSON):** bina schema ke JSON daalo, kabhi bhi field badlo — profile, log, content ke liye
- **Fast chehra (Key-Value + Cache):** chhota data turant nikalo — login, session, setting ke liye

Teeno ek hi transaction me likhe ja sakte hain — ek fail ho to sab wapas (rollback), data adha-adhoora nahi rahega.

**Aaj ki haalat (V0.11):** SQL transactions snapshot isolation ke saath kaam karte hain (BEGIN / COMMIT / ROLLBACK, SAVEPOINT). Lekin cross-model transactional rollback — ek hi transaction me table + document + KV likhna aur ek fail par sab wapas — **implemented nahi hai**. Cache bhi nahi hai (neeche §3 dekho).

Web se seekha: SurrealDB ek engine me document, graph, vector, time-series deta hai. Turso edge par sub-10ms deta hai. ekoDB Rust me ek binary me document + cache + search + vector deta hai. Zeno ka fark: simple install, simple Hindi docs, chhote user ke liye pehle din se kaam kare.

## 3. Fast aur Smooth kaise?
- **Rust:** C jaisi speed, crash kam, no garbage-collector rukawat
- **Do storage:** B-Tree (padhne ke liye fast) + LSM (likhne ke liye fast) — kaam ke hisab se chunega
- **WAL pehle:** likhne se pehle log likhega, light band hone par bhi data safe rahega
- **Memory cache:** baar-baar manga data memory me rakhega
- **PostgreSQL protocol:** purane tools — psql, DBeaver, Python, Node — bina badle chal jayenge
- **Ek file, ek command:** `zeno run` aur chal gaya

Target (V1 ka lakshya, vaada nahi): chhote data par jawab millisecond me, bade data par bhi atakna nahi.

**Aaj ki haalat (V0.11):** Implemented storage WAL → memtable → SSTable hai (LSM-style, B-Tree **nahi** hai). Memory cache **nahi** hai — balki SSTables open par poori memory me load hote hain (Phase 2 me disk-backed SSTable blocks/cache aayega). PostgreSQL protocol implemented hai (Simple + extended, SCRAM-SHA-256, TLS 1.2/1.3). Command `zeno run` **nahi** hai — asli commands `zeno serve`, `put`, `table`, `doc`, `compact` hain (`prototype/README.md` me poora list). Koi speed number claim nahi kiya gaya hai; benchmark sirf Zeno-only hai, comparison nahi.

## 4. High Brand kaise?
- Naam chhota, saaf: Zeno — 4 akshar, bolne me aasan, global
- Tagline: "Zeno — One Engine, All Data"
- Design: black & white minimal, chhota text, saaf docs
- Logo / pehchan baad me — pehle kaam, phir rang

## 5. V1 Scope — pehle chhota, pakka
V1 me sirf ye 5 kaam, aur kuch nahi:
1. Ek node par chalega (single machine)
2. Table banao, data daalo, SQL se nikalo
3. JSON document daalo, nikalo
4. Data band hone par bhi safe rahe (crash ke baad wapas mile)
5. Basic benchmark: PostgreSQL aur MongoDB se compare karke dikhana

V1 me NAHI hoga: multi-node / distributed, cloud hosting, production guarantee.
Ye baad me aayega, jab V1 log use karke batayenge kya chahiye.

**Aaj ki haalat (V0.11):** 1–4 kaam kar rahe hain (4: process-crash recovery test hai; asli power-loss test abhi nahi). 5 **badla hua hai**: benchmark comparison V1 se **baahar** hai — pehle baseline benchmarks + disk-backed SSTable blocks/cache (Phase 2/3) aayenge, comparison uske baad. Kaunsi cheez V1 release blocker hai aur kaunsi post-V1/excluded, woh authoritative list `prototype/docs/V1-READINESS.md` me hai — wahi ek source hai, ye draft nahi.

## 6. Open Source aur Funding ka rasta
1. GitHub par public repo — code, README Hindi + English, demo
2. Log use karenge, issue batayenge, star denge
3. Phir GitHub Sponsors, grants, aur baad me hosted cloud (jisko chalana na ho, wo hamari cloud use kare — wahi se earning)
4. Funding turant nahi aayegi — pehle log, phir paisa. Ye lamba rasta hai.

## 7. Sachchi limit
- Koi database har kaam me duniya ka No.1 nahi hota — speed, safety, scale me hamesha trade-off hota hai.
- Zeno ka vaada: ek khaas kaam me best — **simple + fast + sab data ek jagah**.
- V1 production-ready nahi hoga, test aur audit baaki rahega.
- Naam ka risk: ZenoDB / ZenDB se confusion ho sakta hai — isliye README me pehli line me hi saaf likha jayega: "Zeno is a hybrid SQL + JSON database in Rust, not ZenoDB (time-series) and not ZenDB."

## 8. Agle kadam
1. GitHub repo banao — `zeno` (account: BLOCKCHAINUNIVERSALTECHNOLOGY) — Sanjay ki haan ke baad
2. README + LICENSE (Apache-2.0) + design file daalo
3. V0.1 prototype — key-value + WAL + table + JSON + query chalakar dikhana
4. Benchmark + demo

**Aaj ki haalat (V0.11):** 1–3 ho chuke hain (repo public hai, V0.11 prototype chal raha hai). 4: demo (`prototype/demo.sh`) chal raha hai; benchmark Zeno-only hai, comparison baaki hai.
