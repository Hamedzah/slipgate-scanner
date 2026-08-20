# SlipGate Scanner — Telegram V2Ray/Proxy Intelligence Scanner & Broadcaster

An async Python pipeline that collects V2Ray (VMess/VLESS/Trojan/Shadowsocks/Reality)
and MTProto proxy configs from Telegram channels, rigorously tests them from an
Iran-network perspective, scores them, and broadcasts the best results to a
target Telegram channel with a polished Persian message.

---

## Architecture

```
slipgate-scanner/
├── src/
│   ├── config.py                 # pydantic-settings, loads everything from .env
│   ├── logging_config.py         # structlog JSON logging, secret redaction
│   ├── main.py                   # pipeline orchestrator (entry point)
│   ├── collectors/
│   │   └── telegram_collector.py # Telethon: join channels, fetch messages
│   ├── parsers/
│   │   └── config_parser.py      # vmess/vless/trojan/ss/mtproto URI parsing
│   ├── testing/
│   │   ├── protocol_validator.py # structural validation (UUID, cipher, etc.)
│   │   ├── network_tester.py     # TCP/TLS handshake + xray-core tunnel test
│   │   └── geo.py                # geo/ASN lookup, distance-from-Iran, ISP check
│   ├── scoring/
│   │   └── scorer.py             # weighted composite score (0-100)
│   ├── broadcaster/
│   │   ├── message_formatter.py  # Persian message + re-tagging + buttons
│   │   └── telegram_broadcaster.py
│   ├── storage/
│   │   ├── models.py             # SQLAlchemy ORM models
│   │   └── database.py           # async repository layer, encrypts hosts at rest
│   ├── security/
│   │   └── crypto.py             # Fernet encryption for data at rest
│   └── utils/
│       ├── hashing.py            # SHA-256 dedup
│       ├── rate_limiter.py       # async token-bucket limiter
│       └── metrics.py            # Prometheus metrics
├── scripts/generate_session.py   # one-time local Telethon session generator
├── tests/                        # pytest unit tests
├── .github/workflows/scan.yml    # scheduled run every 4 hours
├── Dockerfile / docker-compose.yml
└── .env.example
```

### Why xray-core directly (not xray-knife)

Tunnel testing shells out to `xray-core` directly via a generated JSON config
and a local SOCKS5 inbound. `xray-knife` was evaluated but its CLI has proven
unstable across recent releases, so this project generates minimal xray
configs itself and manages the subprocess lifecycle directly for a smaller,
more predictable surface area.

### Testing methodology

1. **TCP handshake** — raw connect timing to the proxy's listen port.
2. **TLS handshake** — for TLS/Reality configs, measures handshake time.
3. **Tunnel test** — starts a local xray-core instance and measures true
   end-to-end latency and download throughput (min. 5 MB) *through* the
   proxy, over multiple rounds to estimate jitter and packet/round loss.
4. **Geo/ASN** — resolves exit country, distance from Tehran, and flags
   exits that resolve to Iranian ISPs (MCI, Irancell, TCI, etc.) as
   useless for circumvention.
5. **Protocol validation** — structural checks (valid UUID, supported
   cipher, Reality public key present, etc.) run *before* any network
   call, so malformed configs never waste test time.

> **Note on runner geography:** GitHub-hosted runners are outside Iran.
> Results reflect international reachability, not reachability from behind
> Iranian filtering. Treat scores as a proxy for general quality, not a
> guarantee of accessibility from every ISP.

### Scoring

Composite score = weighted sum of Latency (25%), Speed (25%), Stability (20%),
Geo (15%), and Protocol quality (15%) — all configurable in `.env`. Only
configs scoring ≥ `SCORE_THRESHOLD` (default 70) are broadcast.

---

## Setup (English)

1. **Get Telegram API credentials** at <https://my.telegram.org> → API
   development tools. Note your `api_id` and `api_hash`.

2. **Generate a session string** (one-time, local machine only — never in CI):
   ```bash
   pip install telethon
   TG_API_ID=... TG_API_HASH=... python scripts/generate_session.py
   ```
   Copy the printed string into the `TG_SESSION_STRING` GitHub Secret.

3. **Configure secrets.** Copy `.env.example` to `.env` for local runs, or
   set these as **GitHub Secrets** (repo → Settings → Secrets and variables
   → Actions) for the CI pipeline:
   - `TG_API_ID`, `TG_API_HASH`, `TG_SESSION_STRING`
   - `SOURCE_CHANNELS` (comma-separated handles or invite links)
   - `ENCRYPTION_KEY` — generate with:
     ```bash
     python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
     ```
   Set `TARGET_CHANNEL` as a repository **Variable** (not secret), since it's
   the public destination channel.

4. **Install xray-core** (bundled automatically in Docker and the GitHub
   Actions workflow; for local runs, download from
   <https://github.com/XTLS/Xray-core/releases> and ensure `xray` is on your `PATH`).

5. **Run once locally:**
   ```bash
   pip install -r requirements.txt
   python -m src.main --once
   ```

6. **Run via Docker:**
   ```bash
   docker compose up --build
   ```

7. **Run tests:**
   ```bash
   pytest -q
   ```

The included GitHub Actions workflow (`.github/workflows/scan.yml`) runs one
full cycle every 4 hours automatically — no server required.

---

## راه‌اندازی (فارسی)

۱. **دریافت اطلاعات API تلگرام** از آدرس <https://my.telegram.org> بخش
   API development tools. مقادیر `api_id` و `api_hash` را یادداشت کنید.

۲. **ساخت session string** (فقط یک‌بار، روی سیستم شخصی — هرگز در CI):
   ```bash
   pip install telethon
   TG_API_ID=... TG_API_HASH=... python scripts/generate_session.py
   ```
   رشتهٔ چاپ‌شده را در Secret با نام `TG_SESSION_STRING` در گیت‌هاب ذخیره کنید.

۳. **تنظیم اطلاعات محرمانه.** فایل `.env.example` را به `.env` کپی کنید (برای
   اجرای محلی) یا موارد زیر را به‌عنوان **GitHub Secrets** تنظیم کنید:
   - `TG_API_ID`, `TG_API_HASH`, `TG_SESSION_STRING`
   - `SOURCE_CHANNELS` (لیست کانال‌ها با کاما جدا شده)
   - `ENCRYPTION_KEY` (با دستور بالا تولید کنید)
   نام کانال مقصد (`TARGET_CHANNEL`) را به‌عنوان Variable (نه Secret) تنظیم کنید.

۴. **نصب xray-core** (در Docker و GitHub Actions به‌صورت خودکار نصب می‌شود).

۵. **اجرای محلی:**
   ```bash
   pip install -r requirements.txt
   python -m src.main --once
   ```

۶. **اجرا با Docker:**
   ```bash
   docker compose up --build
   ```

پایپ‌لاین گیت‌هاب اکشنز به‌صورت خودکار هر ۴ ساعت یک‌بار اجرا می‌شود و نیازی به
سرور جداگانه ندارد.

---

## Security notes

- All secrets live in GitHub Secrets / `.env`; none are hard-coded.
- Host/port data is encrypted at rest (Fernet/AES) before being written to
  the database.
- Log output redacts known secret field names automatically.
- Rate limiting (token bucket) protects the Telegram account from flood bans.
- The account used for collection should ideally be a dedicated, disposable
  account rather than a personal one, given it joins many third-party channels.

## Legal / ethical note

This tool re-publishes proxy configurations that channel operators have
already made public. Respect the terms of service of any channel you scrape
and of Telegram itself, and be mindful of the source channels' own licensing
or attribution expectations where applicable.
