# Zeno — Design Draft v0.2 (Hindi, simple)

**Naam FINAL:** Zeno
**Risk note:** Pehle se ZenoDB (Lantern, Go time-series) aur ZenDB hain — Sanjay ne jaan kar risk le kar "Zeno hi rakho" chuna hai (2026-11-15). Isliye hamara Zeno alag pehchan se aayega: "Zeno — One Engine, All Data" tagline, Rust hybrid.
**Type:** General purpose, hybrid, open source database — koi bhi vyakti use kar sakega
**License:** Apache-2.0
**Language:** Rust (fast + safe)

## 1. Ek line me idea
Ek engine, sab data.
Table bhi, Document (JSON) bhi, Key-Value bhi, File bhi — alag-alag database lagane ki zaroorat nahi.

## 2. Creative idea — "Ek Engine, Teen Chehre"
- **Table chehra (SQL):** `CREATE TABLE`, `SELECT`, `JOIN` — bank, shop, app ke pakke data ke liye
- **Document chehra (JSON):** bina schema ke JSON daalo, kabhi bhi field badlo — profile, log, content ke liye
- **Fast chehra (Key-Value + Cache):** chhota data turant nikalo — login, session, setting ke liye

Teeno ek hi transaction me likhe ja sakte hain — ek fail ho to sab wapas (rollback), data adha-adhoora nahi rahega.

Web se seekha: SurrealDB ek engine me document, graph, vector, time-series deta hai. Turso edge par sub-10ms deta hai. ekoDB Rust me ek binary me document + cache + search + vector deta hai. Zeno ka fark: simple install, simple Hindi docs, chhote user ke liye pehle din se kaam kare.

## 3. Fast aur Smooth kaise?
- **Rust:** C jaisi speed, crash kam, no garbage-collector rukawat
- **Do storage:** B-Tree (padhne ke liye fast) + LSM (likhne ke liye fast) — kaam ke hisab se chunega
- **WAL pehle:** likhne se pehle log likhega, light band hone par bhi data safe rahega
- **Memory cache:** baar-baar manga data memory me rakhega
- **PostgreSQL protocol:** purane tools — psql, DBeaver, Python, Node — bina badle chal jayenge
- **Ek file, ek command:** `zeno run` aur chal gaya

Target (V1 ka lakshya, vaada nahi): chhote data par jawab millisecond me, bade data par bhi atakna nahi.

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
