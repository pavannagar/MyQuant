# CoinSwitch Scanner

Chartink-style screener for CoinSwitch PRO spot pairs (USDT/INR). Build conditions
like "close > highest high of last 20 candles AND volume > 2× avg volume" on any
minute interval, scan the whole market, save scanners, and inspect candles per coin.

## Setup

```bash
pip install -r requirements.txt

export COINSWITCH_API_KEY=<your api key>        # Ed25519 public key (hex) from CoinSwitch PRO profile
export COINSWITCH_SECRET_KEY=<your secret key>  # Ed25519 secret key (hex)

uvicorn server:app --host 0.0.0.0 --port 8090
```

Open http://localhost:8090

For systemd, put the two exports in an EnvironmentFile the same way as your
Strategy-Agent service.

## Notes

- Exchanges: `c2c1` / `c2c2` carry the USDT pairs (EVAA/USDT etc.), `coinswitchx` is INR.
- Auth: every request is signed `METHOD + decoded_path + epoch_ms` with Ed25519
  (headers X-AUTH-APIKEY / X-AUTH-SIGNATURE / X-AUTH-EPOCH). Keep your server clock
  NTP-synced — drift > 60s gets rejected with 401.
- Candle fetches are throttled to 5 concurrent with retry/backoff on 429, and cached
  for ~5 min, so re-running a scan (or scanning a universe the server just warmed on
  startup) is cheap. Trade-off: signals can be up to ~5 min stale between fetches.
- "Candle used": Forming = evaluate on the live candle (chartink-style intraday
  breakout); Last closed = only confirmed candles (no repaint).
- Saved scanners persist to `scanners.json` next to server.py.

## API (if you want to hit it from Java)

- `GET  /api/pairs?exchange=c2c1&quote=USDT`
- `GET  /api/candles?symbol=BTC/USDT&exchange=c2c1&interval=15&limit=120`
- `POST /api/scan`           — live, single point-in-time scan. Body: see ScanRequest in server.py
- `POST /api/scan_history`   — walks every candle over a lookback window and evaluates the
  filter at each one; returns every symbol+timestamp that passed with OHLCV.
  Body: ScanRequest fields + `lookback_days` (default 1) or `lookback_candles` (advanced override).
- `GET/POST/DELETE /api/scanners`

## Historical scan (backtest a filter across time)

"Build scanner" has a **Scan mode** dropdown: Live (now) vs **Historical (walk every candle)**.
Historical mode adds a **Lookback** selector (1/2/3/5/7 days) and, instead of one result per
pair, returns every (pair, timestamp) where the filter passed — e.g. "which futures pairs were
trading above VWAP, checked every 5 minutes over the last day". Each row has open/high/low/close/
volume and the candle's IST timestamp. Results render in their own table (capped to the latest
500 rows on screen) with a **⬇ CSV** button that downloads *every* matched row, not just what's
shown. One candle fetch per symbol regardless of lookback length — cheap even for a 7-day walk.

Rows are capped server-side at 20,000 (`truncated: true` in the response) — narrow the universe,
filter, or interval if you hit it.

The **live** Results table also has a ⬇ CSV button (one row per pair, current match only).

## AI scanner builder

Set `ANTHROPIC_API_KEY` in the environment (same EnvironmentFile as the CoinSwitch
keys) and type plain English in the top box, e.g.
"price moved 5% in last 5 min and volume 20% above the 20-candle average".
Claude converts it to a scanner config, fills the builder, and runs it.

## Monitors

Save a scanner, then enable it in the Monitors card — the *server* re-runs it
every 1, 5, 15 minutes or hourly (works even if the browser tab is closed;
results appear when you come back). New hits since the previous run are marked
with ●.

Runs are aligned to the IST wall clock, not to whenever you flipped the
monitor on — e.g. a 5-min monitor fires at :00:01, :05:01, :10:01 IST, an
hourly one at :00:01 IST each hour. The first run after enabling fires
immediately for feedback, then settles onto that boundary.

### WhatsApp alerts (Twilio)

Tick "WhatsApp" next to a monitor to get a message whenever it finds new
matches (no message is sent if there's nothing new — no spam per idle cycle).
Requires these env vars:

```bash
export TWILIO_ACCOUNT_SID=...
export TWILIO_AUTH_TOKEN=...
export TWILIO_WHATSAPP_FROM=whatsapp:+14155238886   # your Twilio WhatsApp sender (sandbox or approved)
export TWILIO_WHATSAPP_TO=whatsapp:+91XXXXXXXXXX    # the recipient number
```

`GET /api/health` reports `whatsapp_configured` so you can confirm it's wired
up. If any of the four vars is missing, alerts are skipped and a warning is
logged — the monitor itself keeps running.

## Rate-limit notes

- Market panel refreshes every 2s (server caches tickers 2s), so upstream load is
  bounded regardless of how many tabs are open.
- Futures klines are capped at 28 req/min by a built-in limiter (CoinSwitch limit: 30).
  Keep futures monitors at "every 5 min" with top_n <= 25, or a 1-min cycle can't finish.

## Production deploy (systemd)

`/etc/coinswitch-scanner.env` (chmod 600):
```
COINSWITCH_API_KEY=...
COINSWITCH_SECRET_KEY=...
ANTHROPIC_API_KEY=...
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
TWILIO_WHATSAPP_TO=whatsapp:+91XXXXXXXXXX
```

`/etc/systemd/system/cs-scanner.service`:
```ini
[Unit]
Description=CoinSwitch Scanner
After=network-online.target

[Service]
WorkingDirectory=/opt/coinswitch-scanner
EnvironmentFile=/etc/coinswitch-scanner.env
ExecStart=/usr/bin/python3 -m uvicorn server:app --host 0.0.0.0 --port 8090 --workers 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`systemctl daemon-reload && systemctl enable --now cs-scanner`

IMPORTANT: exactly ONE worker. Monitors, candle cache, and the futures rate limiter
live in process memory — multiple workers would each run monitors and each burn the
30 req/min futures budget. One async worker easily handles this workload.

NTP-sync the box (Ed25519 auth rejects clock drift). Put nginx in front for TLS
if exposing beyond localhost.
