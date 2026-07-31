"""
CoinSwitch USDT Scanner — chartink-style screener for CoinSwitch PRO spot pairs.

Run:
    export COINSWITCH_API_KEY=...      # Ed25519 public key (hex) from CoinSwitch PRO profile
    export COINSWITCH_SECRET_KEY=...   # Ed25519 secret key (hex)
    pip install -r requirements.txt
    uvicorn server:app --host 0.0.0.0 --port 8090

Then open http://localhost:8090
"""

import asyncio
import base64
import csv
import datetime as _dt
import io
import json
import math
import os
import re
import shutil
import time
import urllib.parse
from pathlib import Path
from typing import Any, Literal, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import logging
log = logging.getLogger("scanner")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------------------------------------------------------------- config ----

BASE_URL = os.getenv("COINSWITCH_BASE_URL", "https://coinswitch.co")
API_KEY = os.getenv("COINSWITCH_API_KEY", "")
SECRET_KEY = os.getenv("COINSWITCH_SECRET_KEY", "")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM", "")   # e.g. "whatsapp:+14155238886"
TWILIO_WHATSAPP_TO = os.getenv("TWILIO_WHATSAPP_TO", "")       # e.g. "whatsapp:+9198xxxxxxx"
WHATSAPP_CONFIGURED = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_WHATSAPP_FROM and TWILIO_WHATSAPP_TO)

# ---------------------------------------------- durable storage (GitHub) ----
# Render's free tier has no persistent disk — anything written to scanners.json survives only
# until the container spins down. When these are set, saved scanners/trash are mirrored to a file
# in this GitHub repo (read once at cold start, written on every save) so they outlive a restart.
# Local files stay in use as the fast-path read cache either way; without these vars set, behavior
# is unchanged (local file only, as before).
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")             # "owner/repo"
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
GITHUB_CONFIGURED = bool(GITHUB_TOKEN and GITHUB_REPO)

# --------------------------------------------------- auto-trading -----------
# Master switch: starts OFF (dry-run) on purpose. A monitor with auto_trade=true only ever
# computes + logs + WhatsApps what it WOULD have traded until this is explicitly set to "1" in
# .env. Flip it only after reviewing several dry-run trades.
LIVE_TRADING = os.getenv("LIVE_TRADING", "0") == "1"
TRADE_LEVERAGE = int(os.getenv("TRADE_LEVERAGE", "5"))
TRADE_RISK_INR = float(os.getenv("TRADE_RISK_INR", "100"))          # rupees risked per trade
TRADE_TARGET_RR = float(os.getenv("TRADE_TARGET_RR", "1"))          # target distance = this * SL distance (1 = 1:1)
TRADE_MAX_PER_DAY = int(os.getenv("TRADE_MAX_PER_DAY", "5"))        # IST-day trade count cap
TRADE_MAX_LOSS_INR_PER_DAY = float(os.getenv("TRADE_MAX_LOSS_INR_PER_DAY", "500"))  # IST-day loss cap

ROOT = Path(__file__).parent
SCANNERS_FILE = ROOT / "scanners.json"
SCANNERS_TRASH_FILE = ROOT / "scanners_trash.json"
MAX_TRASH = 50   # oldest deleted scanners fall off once trash exceeds this

MONITOR_LOG_DIR = ROOT / "monitor_logs"
MONITOR_LOG_DIR.mkdir(exist_ok=True)
MONITOR_LOG_MAX_RUNS = 5000   # oldest runs fall off a scanner's log once it exceeds this (per-file rotation)

CANDLE_CACHE_TTL = 300         # seconds — startup cache warm-up entries stay valid this long
SPOT_CANDLE_CONCURRENCY = 12   # parallel spot candle fetches
FUT_CANDLE_CONCURRENCY = 3     # futures klines are rate-limited upstream
HTTP_TIMEOUT = 20.0


def fresh_candle_ttl(interval_min: int) -> float:
    """Cache TTL for a candle fetch, scaled to the candle period: closed candles never change, so
    we can cache them for ~45% of a candle's length, but the newest (possibly still-forming) candle
    should never be older than that or a scan/backtest silently shows stale data — e.g. a flat 5-min
    TTL on 1m candles could serve a candle set up to 5 candles behind 'now'. Used by every endpoint
    that fetches candles for evaluation (live scan, historical scan, backtest) so they all stay
    equally fresh regardless of which one you run."""
    return min(max(interval_min * 60 * 0.45, 45.0), 600.0)

app = FastAPI(title="CoinSwitch Scanner")
app.add_middleware(GZipMiddleware, minimum_size=1500)

# ------------------------------------------------------------- signing ------

_private_key: Optional[Ed25519PrivateKey] = None


def _get_private_key() -> Ed25519PrivateKey:
    global _private_key
    if _private_key is None:
        if not SECRET_KEY:
            raise HTTPException(500, "COINSWITCH_SECRET_KEY not set")
        _private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SECRET_KEY))
    return _private_key


def sign_request(method: str, endpoint: str, params: Optional[dict] = None):
    """CoinSwitch auth: sign METHOD + decoded_path_with_query + epoch_ms (Ed25519, hex)."""
    if not API_KEY:
        raise HTTPException(500, "COINSWITCH_API_KEY not set")
    path = endpoint
    if params:
        path = endpoint + "?" + urllib.parse.urlencode(params)
    decoded_path = urllib.parse.unquote_plus(path)
    epoch = str(int(time.time() * 1000))
    message = (method.upper() + decoded_path + epoch).encode("utf-8")
    signature = _get_private_key().sign(message).hex()
    headers = {
        "Content-Type": "application/json",
        "X-AUTH-APIKEY": API_KEY,
        "X-AUTH-SIGNATURE": signature,
        "X-AUTH-EPOCH": epoch,
    }
    return headers, decoded_path


_client: Optional[httpx.AsyncClient] = None


def client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(base_url=BASE_URL, timeout=HTTP_TIMEOUT)
    return _client


async def send_whatsapp_message(body: str) -> None:
    """Best-effort WhatsApp alert via Twilio. Never raises — a failed alert shouldn't kill a monitor."""
    if not WHATSAPP_CONFIGURED:
        log.warning("WhatsApp alert skipped — TWILIO_* env vars not fully set")
        return
    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
                             data={"From": TWILIO_WHATSAPP_FROM, "To": TWILIO_WHATSAPP_TO, "Body": body[:1500]})
        if r.status_code >= 300:
            log.warning("Twilio WhatsApp send failed %s: %s", r.status_code, r.text[:300])
    except httpx.HTTPError as e:
        log.warning("Twilio WhatsApp send error: %s", e)


async def cs_get(endpoint: str, params: Optional[dict] = None, retries: int = 3) -> Any:
    last_err = None
    for attempt in range(retries):
        headers, path = sign_request("GET", endpoint, params)
        try:
            r = await client().get(path, headers=headers)
        except httpx.HTTPError as e:
            last_err = f"network error: {e}"
            await asyncio.sleep(0.8 * (attempt + 1))
            continue
        if r.status_code == 429:
            await asyncio.sleep(1.5 * (attempt + 1))
            last_err = "429 rate limited"
            continue
        if r.status_code == 401:
            raise HTTPException(401, "CoinSwitch: Invalid Access — check API/secret key and system clock")
        if r.status_code >= 400:
            raise HTTPException(r.status_code, f"CoinSwitch {r.status_code}: {r.text[:300]}")
        return r.json()
    raise HTTPException(502, f"CoinSwitch request failed after {retries} tries ({last_err})")


async def cs_post(endpoint: str, body: Optional[dict] = None, retries: int = 3) -> Any:
    """CoinSwitch's signature covers only METHOD+path+epoch, never the body — same sign_request()
    as cs_get, just a different HTTP verb and a JSON payload sent unsigned alongside it."""
    last_err = None
    for attempt in range(retries):
        headers, path = sign_request("POST", endpoint)
        try:
            r = await client().post(path, headers=headers, json=body or {})
        except httpx.HTTPError as e:
            last_err = f"network error: {e}"
            await asyncio.sleep(0.8 * (attempt + 1))
            continue
        if r.status_code == 429:
            await asyncio.sleep(1.5 * (attempt + 1))
            last_err = "429 rate limited"
            continue
        if r.status_code == 401:
            raise HTTPException(401, "CoinSwitch: Invalid Access — check API/secret key and system clock")
        if r.status_code >= 400:
            raise HTTPException(r.status_code, f"CoinSwitch {r.status_code}: {r.text[:300]}")
        return r.json()
    raise HTTPException(502, f"CoinSwitch request failed after {retries} tries ({last_err})")


async def cs_delete(endpoint: str, body: Optional[dict] = None, retries: int = 3) -> Any:
    last_err = None
    for attempt in range(retries):
        headers, path = sign_request("DELETE", endpoint)
        try:
            r = await client().request("DELETE", path, headers=headers, json=body or {})
        except httpx.HTTPError as e:
            last_err = f"network error: {e}"
            await asyncio.sleep(0.8 * (attempt + 1))
            continue
        if r.status_code == 429:
            await asyncio.sleep(1.5 * (attempt + 1))
            last_err = "429 rate limited"
            continue
        if r.status_code == 401:
            raise HTTPException(401, "CoinSwitch: Invalid Access — check API/secret key and system clock")
        if r.status_code >= 400:
            raise HTTPException(r.status_code, f"CoinSwitch {r.status_code}: {r.text[:300]}")
        return r.json()
    raise HTTPException(502, f"CoinSwitch request failed after {retries} tries ({last_err})")


# ------------------------------------------------------- market data --------

_ticker_cache: dict[str, tuple[float, dict]] = {}
_candle_cache: dict[tuple, tuple[float, list]] = {}

ALL_EXCHANGES = ["c2c1", "c2c2", "coinswitchx", "futures"]
SPOT_EXCHANGES = ["c2c1", "c2c2", "coinswitchx"]
FUTURES_EXCHANGE_PARAM = "EXCHANGE_2"   # CoinSwitch futures venue id
TICKER_TTL = 2  # seconds — frontend polls every 2s


def resolve_exchanges(exchange: str) -> list[str]:
    if not exchange or exchange.lower() == "all":
        return ALL_EXCHANGES
    if exchange.lower() == "spot":
        return SPOT_EXCHANGES
    return [e.strip().lower() for e in exchange.split(",") if e.strip()]


def fut_display_symbol(sym: str) -> str:
    """BTCUSDT -> BTC/USDT so quote filtering & display match spot."""
    s = sym.upper()
    return s[:-4] + "/USDT" if s.endswith("USDT") and "/" not in s else s


def fut_native_symbol(sym: str) -> str:
    """BTC/USDT -> BTCUSDT for futures endpoints."""
    return sym.replace("/", "").upper()


def _normalize_fut_ticker(t: dict) -> dict:
    return {
        "lastPrice": t.get("last_price", 0),
        "percentageChange": t.get("price_24h_pcnt", 0),
        "baseVolume": t.get("base_asset_volume_24h", 0),
        "quoteVolume": t.get("quote_asset_volume_24h", 0),
        "highPrice": t.get("high_price_24h", 0),
        "lowPrice": t.get("low_price_24h", 0),
        "fundingRate": t.get("funding_rate", 0),
        "openInterest": t.get("open_interest", 0),
    }


async def fetch_all_tickers(exchange: str) -> dict:
    now = time.time()
    hit = _ticker_cache.get(exchange)
    if hit and now - hit[0] < TICKER_TTL:
        return hit[1]
    if exchange == "futures":
        data = await cs_get("/trade/api/v2/futures/all-pairs/ticker",
                            {"exchange": FUTURES_EXCHANGE_PARAM})
        raw = data.get("data", {}) or {}
        tickers = {fut_display_symbol(s): _normalize_fut_ticker(t) for s, t in raw.items()}
    else:
        data = await cs_get("/trade/api/v2/24hr/all-pairs/ticker", {"exchange": exchange})
        tickers = data.get("data", {}) or {}
    _ticker_cache[exchange] = (now, tickers)
    return tickers


async def fetch_merged_tickers(exchange: str):
    """Merge tickers across exchanges -> ({symbol: (exchange, ticker)}, errors).
    On duplicate symbols keep the exchange with higher quote volume."""
    exchanges = resolve_exchanges(exchange)
    results = await asyncio.gather(
        *(fetch_all_tickers(e) for e in exchanges), return_exceptions=True
    )
    merged: dict[str, tuple[str, dict]] = {}
    errors: list[dict] = []
    for exch, res in zip(exchanges, results):
        if isinstance(res, BaseException):
            detail = getattr(res, "detail", None) or str(res)
            errors.append({"exchange": exch, "error": str(detail)[:200]})
            continue
        for sym, t in res.items():
            try:
                qv = float(t.get("quoteVolume", 0) or 0)
            except (ValueError, TypeError):
                qv = 0.0
            prev = merged.get(sym)
            if prev is None:
                merged[sym] = (exch, t)
            elif prev[0] == "futures" and exch != "futures":
                merged[sym] = (exch, t)          # spot always beats futures
            elif exch == "futures" and prev[0] != "futures":
                pass                              # keep spot
            else:
                try:
                    prev_qv = float(prev[1].get("quoteVolume", 0) or 0)
                except (ValueError, TypeError):
                    prev_qv = 0.0
                if qv > prev_qv:
                    merged[sym] = (exch, t)
    return merged, errors


_coins_cache: dict[str, tuple[float, list[str]]] = {}
COINS_TTL = 300  # coin list changes rarely


async def fetch_active_coins(exchange: str) -> list[str]:
    now = time.time()
    hit = _coins_cache.get(exchange)
    if hit and now - hit[0] < COINS_TTL:
        return hit[1]
    if exchange == "futures":
        coins = sorted((await fetch_all_tickers("futures")).keys())
        _coins_cache[exchange] = (now, coins)
        return coins
    data = await cs_get("/trade/api/v2/coins", {"exchange": exchange})
    d = data.get("data", data)
    coins: list[str] = []
    if isinstance(d, dict):  # {"coins": [...]} or {"<exchange>": [...]}
        for v in d.values():
            if isinstance(v, list):
                coins.extend(str(x) for x in v)
    elif isinstance(d, list):
        coins = [str(x) for x in d]
    coins = sorted(set(coins))
    _coins_cache[exchange] = (now, coins)
    return coins


class RateLimiter:
    """Sliding-window limiter (futures klines: 30 req / 60 s)."""

    def __init__(self, max_calls: int, window: float):
        self.max_calls, self.window = max_calls, window
        self.calls: list[float] = []
        self.lock = asyncio.Lock()

    async def wait(self):
        while True:
            async with self.lock:
                now = time.monotonic()
                self.calls = [t for t in self.calls if now - t < self.window]
                if len(self.calls) < self.max_calls:
                    self.calls.append(now)
                    return
                sleep_for = self.window - (now - self.calls[0]) + 0.05
            await asyncio.sleep(max(sleep_for, 0.05))


_fut_kline_limiter = RateLimiter(28, 60.0)


_candle_inflight: dict[tuple, asyncio.Future] = {}


async def fetch_candles(exchange: str, symbol: str, interval: int, n_candles: int,
                        ttl: float = CANDLE_CACHE_TTL) -> list[dict]:
    """Return candles oldest -> newest as [{t, o, h, l, c, v}].
    Concurrent callers for the same key share a single upstream request."""
    key = (exchange, symbol, interval, n_candles)
    now = time.time()
    period_sec = interval * 60
    hit = _candle_cache.get(key)
    # A flat TTL alone isn't enough: a fetch made just before a candle closes stays "fresh" by
    # TTL for a while *after* the close too, so the first request(s) in the new candle period
    # could still serve the previous period's data as "last closed". Also require the cached
    # fetch to belong to the same candle period as now, so the first request after every
    # boundary always forces a fresh fetch.
    if hit and now - hit[0] < ttl and int(hit[0] // period_sec) == int(now // period_sec):
        return hit[1]
    inflight = _candle_inflight.get(key)
    if inflight is not None:
        return await asyncio.shield(inflight)
    fut = asyncio.get_running_loop().create_future()
    _candle_inflight[key] = fut
    try:
        candles = await _fetch_candles_upstream(exchange, symbol, interval, n_candles)
        _candle_cache[key] = (time.time(), candles)
        fut.set_result(candles)
        return candles
    except BaseException as e:
        fut.set_exception(e)
        raise
    finally:
        _candle_inflight.pop(key, None)
        if not fut.done():  # safety net
            fut.cancel()


async def _fetch_candles_upstream(exchange: str, symbol: str, interval: int, n_candles: int) -> list[dict]:
    # Compute the [start,end) window AFTER the rate-limit wait, not before: on a busy scan
    # (many symbols, or several scans/monitors sharing the same limiter) a queued request can
    # sit for minutes before its turn. If end_time were frozen at queue time, the exchange would
    # faithfully return candles only up to that stale timestamp — silently truncating the
    # freshest candles and making "now" mean whenever this call was queued, not when it fired.
    if exchange == "futures":
        await _fut_kline_limiter.wait()

    now = time.time()
    end_ms = int(now * 1000)
    start_ms = end_ms - int(interval * 60_000 * n_candles * 1.25)
    if exchange == "futures":
        data = await cs_get("/trade/api/v2/futures/klines", {
            "exchange": FUTURES_EXCHANGE_PARAM,
            "symbol": fut_native_symbol(symbol),
            "interval": str(interval),
            "start_time": str(start_ms),
            "end_time": str(end_ms),
            "limit": str(min(n_candles, 1000)),
        })
    else:
        data = await cs_get("/trade/api/v2/candles", {
            "exchange": exchange,
            "symbol": symbol,
            "interval": str(interval),
            "start_time": str(start_ms),
            "end_time": str(end_ms),
        })
    raw = data.get("data", []) or []
    candles = []
    for c in raw:
        try:
            candles.append({
                "t": int(c["start_time"]),
                "o": float(c["o"]), "h": float(c["h"]),
                "l": float(c["l"]), "c": float(c["c"]),
                "v": float(c["volume"]),
            })
        except (KeyError, ValueError, TypeError):
            continue
    candles.sort(key=lambda x: x["t"])
    candles = candles[-n_candles:]
    return candles


# ------------------------------------------------------ scan engine ---------

def _series(candles: list[dict], field: str) -> list[float]:
    return [c[field] for c in candles]


def trailing_quote_volume_series(candles: list[dict], bars_per_day: int) -> list[Optional[float]]:
    """Approximate trailing-24h quote volume at each index (sum of volume*close over the last
    `bars_per_day` candles ending at idx) — reconstructs what the ticker's 24h quoteVolume would
    have looked like at that point in history, since the exchange only exposes the current value."""
    out: list[Optional[float]] = [None] * len(candles)
    qv = [c["v"] * c["c"] for c in candles]
    s = 0.0
    for i, v in enumerate(qv):
        s += v
        if i >= bars_per_day:
            s -= qv[i - bars_per_day]
        if i >= bars_per_day - 1:
            out[i] = s
    return out


def _sma(vals: list[float], n: int) -> list[Optional[float]]:
    out: list[Optional[float]] = [None] * len(vals)
    s = 0.0
    for i, v in enumerate(vals):
        s += v
        if i >= n:
            s -= vals[i - n]
        if i >= n - 1:
            out[i] = s / n
    return out


def _ema(vals: list[float], n: int) -> list[Optional[float]]:
    out: list[Optional[float]] = [None] * len(vals)
    if len(vals) < n:
        return out
    k = 2.0 / (n + 1)
    ema = sum(vals[:n]) / n
    out[n - 1] = ema
    for i in range(n, len(vals)):
        ema = vals[i] * k + ema * (1 - k)
        out[i] = ema
    return out


def _rsi(closes: list[float], n: int) -> list[Optional[float]]:
    out: list[Optional[float]] = [None] * len(closes)
    if len(closes) <= n:
        return out
    gains, losses = 0.0, 0.0
    for i in range(1, n + 1):
        d = closes[i] - closes[i - 1]
        gains += max(d, 0)
        losses += max(-d, 0)
    avg_g, avg_l = gains / n, losses / n
    out[n] = 100.0 if avg_l == 0 else 100 - 100 / (1 + avg_g / avg_l)
    for i in range(n + 1, len(closes)):
        d = closes[i] - closes[i - 1]
        avg_g = (avg_g * (n - 1) + max(d, 0)) / n
        avg_l = (avg_l * (n - 1) + max(-d, 0)) / n
        out[i] = 100.0 if avg_l == 0 else 100 - 100 / (1 + avg_g / avg_l)
    return out


def _rolling_extreme(vals: list[float], n: int, fn) -> list[Optional[float]]:
    out: list[Optional[float]] = [None] * len(vals)
    for i in range(n - 1, len(vals)):
        out[i] = fn(vals[i - n + 1:i + 1])
    return out


IST_OFFSET_MS = 19_800_000  # UTC+5:30


def _vwap_daily(candles: list[dict]) -> list[Optional[float]]:
    """Daily-anchored VWAP, day boundary at IST midnight (matches CoinSwitch app).
    If history doesn't reach midnight, the anchor is the first candle of that day slice."""
    out: list[Optional[float]] = [None] * len(candles)
    day = None
    cum_pv = cum_v = 0.0
    for i, c in enumerate(candles):
        d = (c["t"] + IST_OFFSET_MS) // 86_400_000
        if d != day:
            day, cum_pv, cum_v = d, 0.0, 0.0
        tp = (c["h"] + c["l"] + c["c"]) / 3.0
        cum_pv += tp * c["v"]
        cum_v += c["v"]
        out[i] = cum_pv / cum_v if cum_v > 0 else None
    return out


class Operand(BaseModel):
    kind: str                       # price|sma|ema|rsi|highest|lowest|change_pct|number|
                                     # upper_wick_pct|lower_wick_pct|body_pct
    field: str = "close"            # open|high|low|close|volume
    period: int = 14
    offset: int = 0                 # 0 = latest candle, 1 = previous, ...
    value: float = 0.0              # for kind=number


class Condition(BaseModel):
    left: Operand
    op: str                         # gt|lt|gte|lte|crosses_above|crosses_below
    right: Operand
    mult: float = 1.0               # right side multiplier, e.g. volume > 2 x SMA(vol,20)


class ScanRequest(BaseModel):
    exchange: str = "c2c1"
    quote: str = "USDT"
    interval: int = 15              # minutes
    top_n: int = Field(100, le=400)
    min_quote_volume: float = 10000.0
    max_quote_volume: Optional[float] = None   # cap 24h quote volume; None = no cap
    min_change_pct: Optional[float] = None     # only include pairs with 24h % change >= this; None = no filter
    use_last_closed: bool = False   # evaluate on last closed candle instead of forming one
    logic: str = "all"              # all | any
    conditions: list[Condition]
    symbols: list[str] = []         # optional explicit universe (overrides top_n filter)


FIELD_MAP = {"open": "o", "high": "h", "low": "l", "close": "c", "volume": "v"}


def operand_series(op: Operand, candles: list[dict]) -> list[Optional[float]]:
    f = FIELD_MAP.get(op.field, "c")
    if op.kind == "number":
        return [op.value] * len(candles)
    if op.kind == "price":
        return _series(candles, f)  # type: ignore
    if op.kind == "sma":
        return _sma(_series(candles, f), op.period)
    if op.kind == "ema":
        return _ema(_series(candles, f), op.period)
    if op.kind == "rsi":
        return _rsi(_series(candles, "c"), op.period)
    if op.kind == "highest":
        return _rolling_extreme(_series(candles, f), op.period, max)
    if op.kind == "lowest":
        return _rolling_extreme(_series(candles, f), op.period, min)
    if op.kind == "vwap":
        return _vwap_daily(candles)
    if op.kind == "vwap_dist":
        vw = _vwap_daily(candles)
        closes = _series(candles, "c")
        return [None if (v is None or not v) else (c - v) / v * 100
                for c, v in zip(closes, vw)]
    if op.kind == "turnover":
        return [c["c"] * c["v"] for c in candles]
    if op.kind in ("upper_wick_pct", "lower_wick_pct", "body_pct"):
        out_g: list[Optional[float]] = []
        for c in candles:
            rng = c["h"] - c["l"]
            if rng <= 0:
                out_g.append(None)
                continue
            body_top, body_bot = max(c["o"], c["c"]), min(c["o"], c["c"])
            if op.kind == "upper_wick_pct":
                out_g.append((c["h"] - body_top) / rng * 100)
            elif op.kind == "lower_wick_pct":
                out_g.append((body_bot - c["l"]) / rng * 100)
            else:
                out_g.append((body_top - body_bot) / rng * 100)
        return out_g
    if op.kind == "change_pct":
        closes = _series(candles, "c")
        out: list[Optional[float]] = [None] * len(closes)
        for i in range(op.period, len(closes)):
            prev = closes[i - op.period]
            out[i] = (closes[i] - prev) / prev * 100 if prev else None
        return out
    if op.kind == "abs_change_pct":
        closes = _series(candles, "c")
        out: list[Optional[float]] = [None] * len(closes)
        for i in range(op.period, len(closes)):
            prev = closes[i - op.period]
            out[i] = abs((closes[i] - prev) / prev * 100) if prev else None
        return out
    raise HTTPException(400, f"unknown operand kind: {op.kind}")


def value_at(series: list[Optional[float]], idx: int, offset: int) -> Optional[float]:
    j = idx - offset
    if j < 0 or j >= len(series):
        return None
    return series[j]


def eval_condition(cond: Condition, candles: list[dict], idx: int):
    ls = operand_series(cond.left, candles)
    rs = operand_series(cond.right, candles)
    lv = value_at(ls, idx, cond.left.offset)
    rv = value_at(rs, idx, cond.right.offset)
    if lv is None or rv is None:
        return False, lv, rv
    rv_m = rv * cond.mult
    if cond.op == "gt":
        ok = lv > rv_m
    elif cond.op == "lt":
        ok = lv < rv_m
    elif cond.op == "gte":
        ok = lv >= rv_m
    elif cond.op == "lte":
        ok = lv <= rv_m
    elif cond.op in ("crosses_above", "crosses_below"):
        lp = value_at(ls, idx - 1, cond.left.offset)
        rp = value_at(rs, idx - 1, cond.right.offset)
        if lp is None or rp is None:
            return False, lv, rv_m
        rp_m = rp * cond.mult
        if cond.op == "crosses_above":
            ok = lv > rv_m and lp <= rp_m
        else:
            ok = lv < rv_m and lp >= rp_m
    else:
        raise HTTPException(400, f"unknown operator: {cond.op}")
    return ok, lv, rv_m


def condition_series(cond: Condition, candles: list[dict]) -> tuple[list[Optional[float]], list[Optional[float]]]:
    return operand_series(cond.left, candles), operand_series(cond.right, candles)


def eval_at(cond: Condition, ls: list[Optional[float]], rs: list[Optional[float]], idx: int):
    """Same comparison logic as eval_condition, but against precomputed series —
    lets a historical walk evaluate every idx in O(1) instead of recomputing series each time."""
    lv = value_at(ls, idx, cond.left.offset)
    rv = value_at(rs, idx, cond.right.offset)
    if lv is None or rv is None:
        return False, lv, rv
    rv_m = rv * cond.mult
    if cond.op == "gt":
        ok = lv > rv_m
    elif cond.op == "lt":
        ok = lv < rv_m
    elif cond.op == "gte":
        ok = lv >= rv_m
    elif cond.op == "lte":
        ok = lv <= rv_m
    elif cond.op in ("crosses_above", "crosses_below"):
        lp = value_at(ls, idx - 1, cond.left.offset)
        rp = value_at(rs, idx - 1, cond.right.offset)
        if lp is None or rp is None:
            return False, lv, rv_m
        rp_m = rp * cond.mult
        if cond.op == "crosses_above":
            ok = lv > rv_m and lp <= rp_m
        else:
            ok = lv < rv_m and lp >= rp_m
    else:
        raise HTTPException(400, f"unknown operator: {cond.op}")
    return ok, lv, rv_m


def min_valid_idx(conditions: list[Condition]) -> int:
    """First candle index at which every operand in `conditions` has a non-None value
    (e.g. SMA(20) is only valid from index 19 on) — where a historical walk should start."""
    need = 0
    for c in conditions:
        for op in (c.left, c.right):
            if op.kind in ("sma", "ema", "highest", "lowest"):
                need = max(need, op.period - 1 + op.offset)
            elif op.kind == "rsi":
                need = max(need, op.period + op.offset)
            elif op.kind in ("change_pct", "abs_change_pct"):
                need = max(need, op.period + op.offset)
            else:
                need = max(need, op.offset)
        if c.op in ("crosses_above", "crosses_below"):
            need += 1
    return need


def required_lookback(conditions: list[Condition], interval: int) -> int:
    need = 30
    for c in conditions:
        for op in (c.left, c.right):
            if op.kind in ("vwap", "vwap_dist"):
                # candles elapsed since IST midnight + offset margin
                since_mid = ((time.time() * 1000 + IST_OFFSET_MS) % 86_400_000) / 60_000
                need = max(need, min(int(since_mid / max(interval, 1)) + op.offset + 10, 700))
            elif op.kind in ("sma", "ema", "rsi", "highest", "lowest", "change_pct", "abs_change_pct"):
                need = max(need, op.period + op.offset + 5)
            else:
                need = max(need, op.offset + 5)
    need = min(max(need + 20, 60), 700)
    for b in (60, 120, 180, 240, 320, 480, 700):   # bucket -> same cache key across scanners
        if need <= b:
            return b
    return 700


# ------------------------------------------------------------ routes --------

@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "keys_configured": bool(API_KEY and SECRET_KEY),
        "whatsapp_configured": WHATSAPP_CONFIGURED,
        "base_url": BASE_URL,
    }


@app.get("/api/pairs")
async def pairs(exchange: str = "all", quote: str = "USDT"):
    merged, exch_errors = await fetch_merged_tickers(exchange)

    # union with active coins list so pairs with no 24h trades still show up
    exchanges = resolve_exchanges(exchange)
    coin_results = await asyncio.gather(
        *(fetch_active_coins(e) for e in exchanges), return_exceptions=True
    )
    for exch, res in zip(exchanges, coin_results):
        if isinstance(res, BaseException):
            continue
        for sym in res:
            if sym not in merged:
                merged[sym] = (exch, {})

    suffix = "/" + quote.upper()
    want_all = quote.upper() in ("", "ALL")
    rows = []
    for sym, (exch, t) in merged.items():
        if not want_all and not sym.upper().endswith(suffix):
            continue
        try:
            rows.append({
                "symbol": sym,
                "exchange": exch,
                "hasTicker": bool(t),
                "lastPrice": float(t.get("lastPrice", 0) or 0),
                "percentageChange": float(t.get("percentageChange", 0) or 0),
                "baseVolume": float(t.get("baseVolume", 0) or 0),
                "quoteVolume": float(t.get("quoteVolume", 0) or 0),
                "highPrice": float(t.get("highPrice", 0) or 0),
                "lowPrice": float(t.get("lowPrice", 0) or 0),
            })
        except (ValueError, TypeError):
            continue
    rows.sort(key=lambda r: r["quoteVolume"], reverse=True)
    return {"exchange": exchange, "count": len(rows), "pairs": rows, "exchange_errors": exch_errors}


@app.get("/api/find")
async def find_symbol(q: str):
    """Search a coin across every exchange's ticker + active coin list.
    Answers: 'where does CoinSwitch actually list this?'"""
    ql = q.strip().upper()
    if not ql:
        raise HTTPException(400, "q required")
    out, errors = [], []
    for exch in ALL_EXCHANGES:
        tickers: dict = {}
        coins: list[str] = []
        try:
            tickers = await fetch_all_tickers(exch)
        except HTTPException as e:
            errors.append({"exchange": exch, "source": "ticker", "error": str(e.detail)})
        try:
            coins = await fetch_active_coins(exch)
        except HTTPException as e:
            errors.append({"exchange": exch, "source": "coins", "error": str(e.detail)})
        tick_keys = {s.upper(): s for s in tickers}
        for sym in coins:
            if ql in sym.upper():
                out.append({"exchange": exch, "symbol": sym, "source": "coins",
                            "in_ticker": sym.upper() in tick_keys})
        listed = {o["symbol"].upper() for o in out if o["exchange"] == exch}
        for su, s in tick_keys.items():
            if ql in su and su not in listed:
                out.append({"exchange": exch, "symbol": s, "source": "ticker", "in_ticker": True})
    return {"query": q, "matches": out, "errors": errors}


@app.get("/api/candles")
async def candles_route(symbol: str, exchange: str = "all", interval: int = 15,
                        limit: int = 120, max_age: float = 2.0):
    if exchange.lower() == "all":
        merged, _ = await fetch_merged_tickers("all")
        hit = merged.get(symbol)
        exchange = hit[0] if hit else "c2c1"
    ttl = max(0.5, min(max_age, 300.0))
    data = await fetch_candles(exchange, symbol, interval, min(limit, 1000), ttl=ttl)
    last_price = None
    try:
        t = (await fetch_all_tickers(exchange)).get(symbol)
        if t:
            last_price = float(t.get("lastPrice", 0) or 0) or None
    except HTTPException:
        pass
    return {"symbol": symbol, "interval": interval, "exchange": exchange,
            "lastPrice": last_price, "candles": data}


async def resolve_universe(req: ScanRequest) -> tuple[dict, list[str]]:
    """Merged tickers + the ordered symbol universe implied by req's exchange/quote/volume/change
    filters (or req.symbols if given). Shared by the live scan, historical scan, and cache warm-up."""
    merged, _exch_errors = await fetch_merged_tickers(req.exchange)
    if req.symbols:
        return merged, [s for s in req.symbols if s in merged]
    suffix = "/" + req.quote.upper()
    want_all = req.quote.upper() in ("", "ALL")
    rows = []
    for sym, (_exch, t) in merged.items():
        if not want_all and not sym.upper().endswith(suffix):
            continue
        try:
            qv = float(t.get("quoteVolume", 0) or 0)
        except (ValueError, TypeError):
            qv = 0.0
        if qv < req.min_quote_volume:
            continue
        if req.max_quote_volume is not None and qv > req.max_quote_volume:
            continue
        if req.min_change_pct is not None:
            try:
                chg = float(t.get("percentageChange", 0) or 0)
            except (ValueError, TypeError):
                chg = 0.0
            if chg < req.min_change_pct:
                continue
        rows.append((sym, qv))
    rows.sort(key=lambda x: x[1], reverse=True)
    return merged, [s for s, _ in rows[:req.top_n]]


async def run_scan(req: ScanRequest) -> dict:
    if not req.conditions:
        raise HTTPException(400, "add at least one condition")

    merged, universe = await resolve_universe(req)
    lookback = required_lookback(req.conditions, req.interval)
    # the forming candle is also patched with the live ticker price below.
    scan_ttl = fresh_candle_ttl(req.interval)
    spot_sem = asyncio.Semaphore(SPOT_CANDLE_CONCURRENCY)
    fut_sem = asyncio.Semaphore(FUT_CANDLE_CONCURRENCY)
    matches, errors = [], []

    async def scan_symbol(sym: str):
        sym_exch, tick = merged.get(sym, ("c2c1", {}))
        sem = fut_sem if sym_exch == "futures" else spot_sem
        async with sem:
            try:
                candles = await fetch_candles(sym_exch, sym, req.interval, lookback, ttl=scan_ttl)
            except HTTPException as e:
                errors.append({"symbol": sym, "error": str(e.detail)})
                return
        if len(candles) < 3:
            return
        if not req.use_last_closed:
            try:
                lp = float(tick.get("lastPrice", 0) or 0)
            except (ValueError, TypeError):
                lp = 0.0
            if lp > 0:
                last = dict(candles[-1])
                last["c"] = lp
                last["h"] = max(last["h"], lp)
                last["l"] = min(last["l"], lp)
                candles = candles[:-1] + [last]
        idx = len(candles) - 2 if (req.use_last_closed and len(candles) >= 2) else len(candles) - 1
        results, passed_any, passed_all = [], False, True
        for cond in req.conditions:
            ok, lv, rv = eval_condition(cond, candles, idx)
            results.append({"ok": ok, "left": lv, "right": rv})
            passed_any = passed_any or ok
            passed_all = passed_all and ok
        if (req.logic == "any" and passed_any) or (req.logic != "any" and passed_all):
            t = merged.get(sym, (sym_exch, {}))[1]
            eval_candle = candles[idx]
            matches.append({
                "symbol": sym,
                "exchange": sym_exch,
                "lastPrice": float(t.get("lastPrice", 0) or 0),
                "percentageChange": float(t.get("percentageChange", 0) or 0),
                "quoteVolume": float(t.get("quoteVolume", 0) or 0),
                "candleClose": eval_candle["c"],
                "candleLow": eval_candle["l"],
                "candleHigh": eval_candle["h"],
                "candleVolume": eval_candle["v"],
                "candleTime": eval_candle["t"],
                "conditions": results,
            })

    started = time.time()
    await asyncio.gather(*(scan_symbol(s) for s in universe))
    matches.sort(key=lambda m: m["quoteVolume"], reverse=True)
    took_ms = int((time.time() - started) * 1000)
    log.info("scan: %s pairs, %s matched, %sms (interval=%sm, exch=%s)",
             len(universe), len(matches), took_ms, req.interval, req.exchange)
    return {
        "scanned": len(universe),
        "matched": len(matches),
        "interval": req.interval,
        "took_ms": took_ms,
        "matches": matches,
        "errors": errors[:10],
    }


@app.post("/api/scan")
async def scan(req: ScanRequest):
    return await run_scan(req)


# --------------------------------------------------- historical scan --------

class HistoryScanRequest(ScanRequest):
    lookback_days: float = Field(1.0, gt=0, le=30)         # how far back to walk, at `interval`
    lookback_candles: Optional[int] = None                  # advanced override; if set, ignore lookback_days


MAX_HISTORY_MATCHES = 20000   # safety cap on returned rows (narrow filter/interval if you hit this)


def history_scan_sizing(req: HistoryScanRequest) -> tuple[int, int, int]:
    """(warmup, n_candles, bars_per_day) for a historical walk: warmup is the first evaluable index
    (also where change_pct_24h/prev-candle become valid), n_candles is how much history to fetch."""
    bars_per_day = max(1, round(1440 / max(req.interval, 1)))
    # extra history before the scanned window so change_pct_24h has a same-time-yesterday candle to
    # compare against for (almost) every returned row — capped so tiny intervals don't blow the
    # upstream ~1000-candle ceiling (at 1m/24h that ceiling is unavoidable; chg_24h falls back to None there).
    chg_buffer = min(bars_per_day, 400)
    warmup = max(min_valid_idx(req.conditions), chg_buffer)
    bars = req.lookback_candles if req.lookback_candles else max(5, round(req.lookback_days * 1440 / max(req.interval, 1)))
    return warmup, min(warmup + bars + 2, 1000), bars_per_day


async def run_history_scan(req: HistoryScanRequest) -> dict:
    """Walk every historical candle over the lookback window (not just the latest one) and
    evaluate the filter at each point in time, for each symbol in the universe. Returns every
    symbol+timestamp that passed with OHLC + volume — the building block for the CSV export."""
    if not req.conditions:
        raise HTTPException(400, "add at least one condition")

    merged, universe = await resolve_universe(req)
    warmup, n_candles, bars_per_day = history_scan_sizing(req)
    bars = req.lookback_candles if req.lookback_candles else max(5, round(req.lookback_days * 1440 / max(req.interval, 1)))
    hist_ttl = fresh_candle_ttl(req.interval)

    spot_sem = asyncio.Semaphore(SPOT_CANDLE_CONCURRENCY)
    fut_sem = asyncio.Semaphore(FUT_CANDLE_CONCURRENCY)
    matches: list[dict] = []
    errors: list[dict] = []
    truncated = False

    async def scan_symbol(sym: str):
        nonlocal truncated
        sym_exch, _tick = merged.get(sym, ("c2c1", {}))
        sem = fut_sem if sym_exch == "futures" else spot_sem
        async with sem:
            try:
                candles = await fetch_candles(sym_exch, sym, req.interval, n_candles, ttl=hist_ttl)
            except HTTPException as e:
                errors.append({"symbol": sym, "error": str(e.detail)})
                return
        if len(candles) <= warmup + 1:
            return
        cond_series = [condition_series(cond, candles) for cond in req.conditions]
        chg_1candle = operand_series(Operand(kind="change_pct", period=1), candles)
        chg_24h = operand_series(Operand(kind="change_pct", period=bars_per_day), candles)
        end_idx = len(candles) - (2 if req.use_last_closed else 1)
        for idx in range(warmup, end_idx + 1):
            passed_any, passed_all = False, True
            for cond, (ls, rs) in zip(req.conditions, cond_series):
                ok, _lv, _rv = eval_at(cond, ls, rs, idx)
                passed_any = passed_any or ok
                passed_all = passed_all and ok
            if (req.logic == "any" and passed_any) or (req.logic != "any" and passed_all):
                if len(matches) >= MAX_HISTORY_MATCHES:
                    truncated = True
                    continue
                c = candles[idx]
                matches.append({
                    "symbol": sym, "exchange": sym_exch, "time": c["t"],
                    "open": c["o"], "high": c["h"], "low": c["l"],
                    "close": c["c"], "volume": c["v"],
                    "change_pct_prev_candle": chg_1candle[idx],
                    "change_pct_24h": chg_24h[idx],
                })

    started = time.time()
    await asyncio.gather(*(scan_symbol(s) for s in universe))
    matches.sort(key=lambda m: (m["time"], m["symbol"]))
    took_ms = int((time.time() - started) * 1000)
    log.info("history scan: %s pairs, %s events, %sms (interval=%sm, bars=%s, exch=%s)",
             len(universe), len(matches), took_ms, req.interval, bars, req.exchange)
    return {
        "scanned": len(universe),
        "matched_events": len(matches),
        "symbols_matched": len({m["symbol"] for m in matches}),
        "interval": req.interval,
        "lookback_days": req.lookback_days,
        "bars_per_symbol": bars,
        "took_ms": took_ms,
        "truncated": truncated,
        "matches": matches,
        "errors": errors[:10],
    }


@app.post("/api/scan_history")
async def scan_history(req: HistoryScanRequest):
    return await run_history_scan(req)


# ------------------------------------------------------- backtest engine ----
#
# Long or short trade simulation per signal, entry = signal candle's close:
#   long:  stop-loss = signal candle's low,  favorable direction is price UP
#   short: stop-loss = signal candle's high, favorable direction is price DOWN
#   walk forward candle-by-candle from the signal. Each candle is checked SL
#   first, then target (conservative — if a single candle could satisfy both
#   with no intraday tick data, assume the stop triggers first):
#     long:  low <= SL -> stopped out, loss, RR = -1 | high >= target -> win, RR = target_rr
#     short: high >= SL -> stopped out, loss, RR = -1 | low <= target -> win, RR = target_rr
#   otherwise the running most-favorable price is tracked (max_price / max_rr,
#   highest high for long / lowest low for short) through to "now".
#   Without a target_rr (the default): every trade settles as win (SL never
#   hit) or loss (SL hit), exactly as before.
#   With a target_rr: a trade that hits neither SL nor target yet is "open" —
#   still running, not yet a settled win or loss; its rr is the *unrealized*
#   R multiple at the current price.
#   max_rr is always reported regardless of outcome — "I got stopped for -1R,
#   but this trade actually reached +2.3R before it reversed."
#   A signal with very few forward candles ("bars_after_signal") hasn't had
#   time to play out yet — interpret its result cautiously.

def simulate_trade(candles: list[dict], idx: int, target_rr: Optional[float] = None,
                    trail_to_breakeven: bool = False, direction: str = "long",
                    sl_pct: Optional[float] = None) -> dict:
    sign = 1.0 if direction == "long" else -1.0   # +1: favorable = price up. -1: favorable = price down.
    entry = candles[idx]["c"]
    candle_extreme = candles[idx]["l"] if direction == "long" else candles[idx]["h"]
    # sl_pct: how far of the close-to-extreme distance the stop sits at, as a percent.
    #   None or 100 -> full candle low/high (the original fixed behaviour).
    #   50 -> halfway between close and the candle's low/high ("candle half").
    #   30 -> 30% of the way from close toward the low/high.
    frac = 1.0 if sl_pct is None else max(0.0, min(100.0, sl_pct)) / 100.0
    sl = entry - frac * (entry - candle_extreme)   # frac=1 -> candle_extreme (old fixed SL), frac=0.5 -> midpoint
    risk = sign * (entry - sl)   # always positive when SL is placed on the correct side of entry
    target_price = (entry + sign * target_rr * risk) if (target_rr is not None and risk > 0) else None
    # once price reaches 1:1 (1R profit), the stop moves to entry (cost-to-cost / breakeven) —
    # a later stop-out at that level is a scratch (0R), not a loss.
    breakeven_trigger = (entry + sign * risk) if (trail_to_breakeven and risk > 0) else None
    effective_sl = sl
    breakeven_triggered = False
    breakeven_triggered_time = None
    max_price = entry   # "most favorable price reached" — highest high (long) or lowest low (short)
    sl_hit = False
    sl_hit_time = None
    target_hit = False
    target_hit_time = None
    bars_after = 0
    for j in range(idx + 1, len(candles)):
        c = candles[j]
        bars_after += 1
        stop_touched = c["l"] <= effective_sl if direction == "long" else c["h"] >= effective_sl
        if stop_touched:
            sl_hit = True
            sl_hit_time = c["t"]
            break
        target_touched = (target_price is not None and
                           (c["h"] >= target_price if direction == "long" else c["l"] <= target_price))
        if target_touched:
            target_hit = True
            target_hit_time = c["t"]
            fav = c["h"] if direction == "long" else c["l"]
            max_price = max(max_price, fav) if direction == "long" else min(max_price, fav)
            break
        be_touched = (breakeven_trigger is not None and not breakeven_triggered and
                      (c["h"] >= breakeven_trigger if direction == "long" else c["l"] <= breakeven_trigger))
        if be_touched:
            breakeven_triggered = True
            breakeven_triggered_time = c["t"]
            effective_sl = entry   # protects from here on; doesn't retroactively affect this candle's SL check above
        fav = c["h"] if direction == "long" else c["l"]
        if (fav > max_price) if direction == "long" else (fav < max_price):
            max_price = fav
    current_price = candles[-1]["c"]
    pct_move = sign * (max_price - entry) / entry * 100 if entry else 0.0
    max_rr = None if risk <= 0 else sign * (max_price - entry) / risk

    # target_hit can only be True when target_rr was actually set (target_price is None otherwise),
    # so this same logic correctly covers both modes:
    #   no target_rr -> every non-stopped trade is "open" (nothing to call a settled win against)
    #   target_rr set -> "win" only once price actually reaches it
    if sl_hit:
        if breakeven_triggered:
            status, rr = "breakeven", 0.0   # stopped at cost after 1R was already banked — a scratch, not a loss
        else:
            status, rr = "loss", (None if risk <= 0 else -1.0)
    elif target_hit:
        status, rr = "win", target_rr
    else:
        status = "open"
        rr = None if risk <= 0 else sign * (current_price - entry) / risk   # unrealized, still running

    return {
        "direction": direction,
        "entry": entry, "sl": sl, "max_price": max_price, "max_rr": max_rr,
        "sl_hit": sl_hit, "sl_hit_time": sl_hit_time,
        "target_hit": target_hit, "target_hit_time": target_hit_time,
        "breakeven_triggered": breakeven_triggered, "breakeven_triggered_time": breakeven_triggered_time,
        "current_price": current_price, "status": status, "is_win": status == "win",
        "rr": rr, "pct_move": pct_move, "bars_after_signal": bars_after,
    }


def summarize_trades(trades: list[dict]) -> dict:
    total = len(trades)
    wins = sum(1 for t in trades if t["status"] == "win")
    losses = sum(1 for t in trades if t["status"] == "loss")
    breakevens = sum(1 for t in trades if t["status"] == "breakeven")
    opens = sum(1 for t in trades if t["status"] == "open")
    settled = wins + losses   # win_rate excludes breakevens (scratches) same as it excludes opens
    rrs = [t["rr"] for t in trades if t["rr"] is not None and t["status"] != "open"]
    win_rrs = [t["rr"] for t in trades if t["status"] == "win" and t["rr"] is not None]
    loss_rrs = [t["rr"] for t in trades if t["status"] == "loss" and t["rr"] is not None]
    open_rrs = [t["rr"] for t in trades if t["status"] == "open" and t["rr"] is not None]
    max_rrs = [t["max_rr"] for t in trades if t["max_rr"] is not None]
    return {
        "total": total,
        "wins": wins,
        "losses": losses,
        "breakevens": breakevens,
        "open": opens,
        "win_rate": (wins / settled * 100) if settled else 0.0,
        "avg_rr": (sum(rrs) / len(rrs)) if rrs else 0.0,
        "avg_rr_win": (sum(win_rrs) / len(win_rrs)) if win_rrs else 0.0,
        "avg_rr_loss": (sum(loss_rrs) / len(loss_rrs)) if loss_rrs else 0.0,
        "avg_open_rr": (sum(open_rrs) / len(open_rrs)) if open_rrs else 0.0,
        "avg_max_rr": (sum(max_rrs) / len(max_rrs)) if max_rrs else 0.0,
        "avg_pct_move": (sum(t["pct_move"] for t in trades) / total) if total else 0.0,
        "expectancy_r": (sum(rrs) / len(rrs)) if rrs else 0.0,
    }


MAX_BACKTEST_TRADES = 20000   # safety cap on returned trades (narrow filter/interval if you hit this)


class BacktestRequest(HistoryScanRequest):
    target_rr: Optional[float] = Field(None, gt=0)   # e.g. 4 = take profit at 4x the SL risk (1:4).
                                                       # None (default) = no target, ride to max / SL only.
    trail_to_breakeven: bool = False   # once price reaches 1:1, move SL to entry — a later stop-out
                                        # there is a scratch (0R, status "breakeven"), not a loss.
    direction: Literal["long", "short"] = "long"   # long: SL = signal candle low. short: SL = signal candle high.
    sl_pct: Optional[float] = Field(None, gt=0, le=100)   # % of the close-to-extreme distance the SL sits at.
                                                            # None/100 = full candle low/high (default, unchanged).
                                                            # 50 = halfway between close and low/high. 30 = 30% of
                                                            # the way from close toward the low/high.


BACKTEST_CANDIDATE_POOL = 100   # how many symbols (by today's current volume) to fetch history for,
                                 # then re-rank at every historical bar by that bar's own trailing
                                 # 24h volume/change — bounded so a futures backtest (28 req/min
                                 # upstream limit) finishes in a few minutes instead of ~25 for all 648 pairs.
BACKTEST_CANDLE_CACHE_TTL = 3600   # backtest candles are historical, not live-sensitive, so cache them
                                    # far longer than a live scan would (fresh_candle_ttl caps at 600s) —
                                    # re-running/tweaking a backtest within the hour reuses the same fetch.


async def run_backtest(req: BacktestRequest) -> dict:
    """Same signal-detection walk as run_history_scan, but every signal is turned into a
    simulated long trade (simulate_trade) instead of a bare OHLCV row.

    The scan universe (top_n by quote volume) is reconstructed *per historical bar* from each
    candidate's own trailing-24h volume/change at that bar — not from today's live ticker — so a
    symbol only counts as "in the top_n" for a given hour if it actually would have ranked there
    back then. Candidates are still pre-selected by today's volume (capped at
    BACKTEST_CANDIDATE_POOL) since that's the only ranking the exchange's ticker exposes; a symbol
    that was significant historically but has since gone quiet may be missed.
    """
    if not req.conditions:
        raise HTTPException(400, "add at least one condition")

    pool_size = max(req.top_n, BACKTEST_CANDIDATE_POOL)
    candidate_req = req.model_copy(update={
        "top_n": pool_size, "min_quote_volume": 0.0, "max_quote_volume": None, "min_change_pct": None,
    })
    merged, universe = await resolve_universe(candidate_req)
    warmup, n_candles, bars_per_day = history_scan_sizing(req)
    bars = req.lookback_candles if req.lookback_candles else max(5, round(req.lookback_days * 1440 / max(req.interval, 1)))

    spot_sem = asyncio.Semaphore(SPOT_CANDLE_CONCURRENCY)
    fut_sem = asyncio.Semaphore(FUT_CANDLE_CONCURRENCY)
    errors: list[dict] = []
    symbol_data: dict[str, dict] = {}

    async def fetch_symbol(sym: str):
        sym_exch, _tick = merged.get(sym, ("c2c1", {}))
        sem = fut_sem if sym_exch == "futures" else spot_sem
        async with sem:
            try:
                candles = await fetch_candles(sym_exch, sym, req.interval, n_candles, ttl=BACKTEST_CANDLE_CACHE_TTL)
            except HTTPException as e:
                errors.append({"symbol": sym, "error": str(e.detail)})
                return
        if len(candles) <= warmup + 1:
            return
        symbol_data[sym] = {
            "exchange": sym_exch,
            "candles": candles,
            "cond_series": [condition_series(cond, candles) for cond in req.conditions],
            "trailing_qv": trailing_quote_volume_series(candles, bars_per_day),
            "chg24h": operand_series(Operand(kind="change_pct", period=bars_per_day), candles),
        }

    started = time.time()
    await asyncio.gather(*(fetch_symbol(s) for s in universe))

    trades: list[dict] = []
    truncated = False
    end_idx = n_candles - (2 if req.use_last_closed else 1)
    for idx in range(warmup, end_idx + 1):
        ranked = []
        for sym, d in symbol_data.items():
            candles = d["candles"]
            if idx >= len(candles):
                continue
            qv = d["trailing_qv"][idx]
            if qv is None or qv < req.min_quote_volume:
                continue
            if req.max_quote_volume is not None and qv > req.max_quote_volume:
                continue
            if req.min_change_pct is not None:
                chg = d["chg24h"][idx]
                if chg is None or chg < req.min_change_pct:
                    continue
            ranked.append((sym, qv))
        ranked.sort(key=lambda x: x[1], reverse=True)
        for sym, _qv in ranked[:req.top_n]:
            d = symbol_data[sym]
            passed_any, passed_all = False, True
            for cond, (ls, rs) in zip(req.conditions, d["cond_series"]):
                ok, _lv, _rv = eval_at(cond, ls, rs, idx)
                passed_any = passed_any or ok
                passed_all = passed_all and ok
            if (req.logic == "any" and passed_any) or (req.logic != "any" and passed_all):
                if len(trades) >= MAX_BACKTEST_TRADES:
                    truncated = True
                    continue
                candles = d["candles"]
                sim = simulate_trade(candles, idx, req.target_rr, req.trail_to_breakeven, req.direction, req.sl_pct)
                trades.append({
                    "symbol": sym, "exchange": d["exchange"], "signal_time": candles[idx]["t"],
                    **sim,
                })

    trades.sort(key=lambda t: (t["signal_time"], t["symbol"]))
    took_ms = int((time.time() - started) * 1000)
    summary = summarize_trades(trades)
    log.info("backtest: %s candidates, %s trades, win_rate=%.1f%%, %sms (interval=%sm, bars=%s, exch=%s)",
              len(universe), len(trades), summary["win_rate"], took_ms, req.interval, bars, req.exchange)
    return {
        "scanned": len(universe),
        "signals": len(trades),
        "interval": req.interval,
        "lookback_days": req.lookback_days,
        "bars_per_symbol": bars,
        "target_rr": req.target_rr,
        "trail_to_breakeven": req.trail_to_breakeven,
        "direction": req.direction,
        "sl_pct": req.sl_pct,
        "took_ms": took_ms,
        "truncated": truncated,
        "summary": summary,
        "trades": trades,
        "errors": errors[:10],
    }


@app.post("/api/backtest")
async def backtest_route(req: BacktestRequest):
    return await run_backtest(req)


# --------------------------------------------------- saved backtests --------

BACKTESTS_FILE = ROOT / "backtests.json"


def _load_backtests() -> list[dict]:
    if BACKTESTS_FILE.exists():
        try:
            return json.loads(BACKTESTS_FILE.read_text())
        except json.JSONDecodeError:
            return []
    return []


def _save_backtests(items: list[dict]):
    BACKTESTS_FILE.write_text(json.dumps(items, indent=2))


class SavedBacktest(BaseModel):
    name: str
    config: dict
    result: dict


@app.get("/api/backtests")
async def list_backtests():
    """Lightweight card-view listing — summary only, not the full trade log (fetch by id for that)."""
    items = _load_backtests()
    out = [{
        "id": b["id"], "name": b["name"], "version": b["version"], "saved_at": b["saved_at"],
        "summary": b.get("result", {}).get("summary", {}),
        "interval": b.get("config", {}).get("interval"),
        "lookback_days": b.get("config", {}).get("lookback_days"),
    } for b in items]
    out.sort(key=lambda x: x["saved_at"], reverse=True)
    return {"backtests": out}


@app.get("/api/backtests/{id}")
async def get_backtest(id: str):
    items = _load_backtests()
    b = next((x for x in items if x["id"] == id), None)
    if b is None:
        raise HTTPException(404, f"backtest '{id}' not found")
    return b


@app.post("/api/backtests")
async def save_backtest(item: SavedBacktest):
    """Always creates a new version under `name` — never overwrites — so you can save the
    same filter's backtest repeatedly over time (or under different tweaks) and compare."""
    items = _load_backtests()
    version = max((b["version"] for b in items if b["name"] == item.name), default=0) + 1
    entry = {
        "id": f"{item.name}__v{version}__{int(time.time() * 1000)}",
        "name": item.name,
        "version": version,
        "config": item.config,
        "result": item.result,
        "saved_at": int(time.time() * 1000),
    }
    items.append(entry)
    _save_backtests(items)
    return {"ok": True, "id": entry["id"], "version": version}


@app.delete("/api/backtests/{id}")
async def delete_backtest(id: str):
    items = _load_backtests()
    new = [b for b in items if b["id"] != id]
    _save_backtests(new)
    return {"ok": True, "deleted": len(items) - len(new)}


# ------------------------------------------------ AI scanner builder --------

NL2SCAN_SYSTEM = """You convert plain-English crypto screener requests into JSON for a scanner engine.

Output ONLY a JSON object, no markdown fences, no prose:
{"config": {...}, "explanation": "<one short sentence describing the scan>"}

config schema:
- interval: candle minutes, one of 1,5,15,30,60,240,1440 (infer from the request; default 15)
- exchange: "all" | "spot" | "futures" (default "all")
- quote: "USDT" (default) | "INR" | "ALL"
- top_n: int universe size by 24h volume (default 80)
- min_quote_volume: float (default 10000)
- use_last_closed: bool (default false; true if user says "confirmed/closed candles")
- logic: "all" | "any" (default "all")
- conditions: list of {left, op, right, mult}
  - op: "gt" | "gte" | "lt" | "lte" | "crosses_above" | "crosses_below"
  - mult: number multiplying the RIGHT side (default 1). "20% more than X" => right=X, mult=1.2
  - operand {kind, field, period, offset, value}:
    - kind "price": current candle value; field one of open/high/low/close/volume; offset = candles ago (0=latest)
    - kind "sma"/"ema": moving average of field over period
    - kind "rsi": RSI of close over period
    - kind "highest"/"lowest": rolling max/min of field over period (offset 1 = excluding current candle)
    - kind "change_pct": % change of close over the last `period` candles
    - kind "vwap": daily-anchored VWAP value (resets at UTC midnight)
    - kind "vwap_dist": signed % distance of close from daily VWAP; 0.3 means 0.3% above, -0.5 means 0.5% below
    - kind "turnover": candle traded value in USDT (close x volume). "$1 million traded" => turnover > number 1000000
    - kind "number": constant; set value

"near VWAP" => vwap_dist between -X and +X (two conditions, logic "all").
"pulled back to VWAP after being above it" => vwap_dist at an earlier offset > threshold AND vwap_dist now between small bounds.

Examples:
"coins trading within 0.3% of vwap on 5m" =>
{"config":{"interval":5,"exchange":"all","quote":"USDT","top_n":80,"min_quote_volume":10000,"use_last_closed":false,"logic":"all","conditions":[
 {"left":{"kind":"vwap_dist","field":"close","period":1,"offset":0,"value":0},"op":"lt","right":{"kind":"number","field":"close","period":1,"offset":0,"value":0.3},"mult":1},
 {"left":{"kind":"vwap_dist","field":"close","period":1,"offset":0,"value":0},"op":"gt","right":{"kind":"number","field":"close","period":1,"offset":0,"value":-0.3},"mult":1}
]},"explanation":"5m: close within ±0.3% of daily VWAP"}

"price moved 5% in last 5 minutes and volume 20% above 20-candle average on 5m" =>
{"config":{"interval":5,"exchange":"all","quote":"USDT","top_n":80,"min_quote_volume":10000,"use_last_closed":false,"logic":"all","conditions":[
 {"left":{"kind":"change_pct","field":"close","period":1,"offset":0,"value":0},"op":"gt","right":{"kind":"number","field":"close","period":1,"offset":0,"value":5},"mult":1},
 {"left":{"kind":"price","field":"volume","period":1,"offset":0,"value":0},"op":"gt","right":{"kind":"sma","field":"volume","period":20,"offset":1,"value":0},"mult":1.2}
]},"explanation":"5m candles: close up >5% in one candle and volume >1.2x the 20-candle average"}

"rsi below 30 on hourly" =>
{"config":{"interval":60,"exchange":"all","quote":"USDT","top_n":80,"min_quote_volume":10000,"use_last_closed":false,"logic":"all","conditions":[
 {"left":{"kind":"rsi","field":"close","period":14,"offset":0,"value":0},"op":"lt","right":{"kind":"number","field":"close","period":1,"offset":0,"value":30},"mult":1}
]},"explanation":"1h candles: RSI(14) below 30"}

If the user says "dropped/fell X%", use op "lt" with value -X. Always fill every operand key."""


class NLQuery(BaseModel):
    query: str


@app.post("/api/nl2scan")
async def nl2scan(q: NLQuery):
    key = os.getenv("ANTHROPIC_API_KEY", "")
    if not key:
        raise HTTPException(500, "Set ANTHROPIC_API_KEY in the environment to use the AI builder")
    if not q.query.strip():
        raise HTTPException(400, "empty query")
    async with httpx.AsyncClient(timeout=45.0) as c:
        r = await c.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": "claude-sonnet-4-6", "max_tokens": 1200,
                  "system": NL2SCAN_SYSTEM,
                  "messages": [{"role": "user", "content": q.query.strip()}]},
        )
    if r.status_code >= 400:
        raise HTTPException(502, f"Anthropic API {r.status_code}: {r.text[:200]}")
    try:
        text = "".join(b.get("text", "") for b in r.json().get("content", []))
        text = text.replace("```json", "").replace("```", "").strip()
        out = json.loads(text)
        cfg = out["config"]
        ScanRequest(**cfg)  # validate before returning
        return {"config": cfg, "explanation": out.get("explanation", "")}
    except (KeyError, ValueError, TypeError) as e:
        raise HTTPException(502, f"AI returned an invalid scanner: {e}")


# ---------------------------------------------------- monitors --------------

_monitor_state: dict[str, dict] = {}

MONITOR_ALIGN_BUFFER_SEC = 1  # small cushion so the just-closed candle/ticker has landed


def _next_aligned_run(every_sec: int, now: Optional[float] = None) -> float:
    """Next UTC-epoch boundary for every_sec, +buffer — matches the exchange's own candle
    close times (candles are UTC-hour aligned upstream). For 1/5/15 min this lands on the
    same instants as IST clock marks (:00,:05,:10... IST) since IST_OFFSET_MS is a whole
    number of those periods. For hourly (3600s) it lands on IST :30 marks (e.g. 11:30,
    12:30... IST) rather than IST top-of-hour, because IST is UTC+5:30 — a half-hour
    offset that top-of-hour IST alignment used to miss, firing 30 min away from the real
    candle close.
    Keeps monitors firing on the clock instead of drifting from whenever the monitor
    happened to be enabled."""
    now = now if now is not None else time.time()
    next_epoch = (int(now // every_sec) + 1) * every_sec
    return next_epoch + MONITOR_ALIGN_BUFFER_SEC


class MonitorCfg(BaseModel):
    enabled: bool
    every_sec: int = 300     # 60 / 300 / 900 / 3600
    whatsapp: bool = False   # send a WhatsApp alert (via Twilio) on new matches
    auto_trade: bool = False  # place a real (or dry-run, per LIVE_TRADING) futures trade on new matches


@app.post("/api/monitors/{name}")
async def set_monitor(name: str, cfg: MonitorCfg):
    items = _load_scanners()
    for s in items:
        if s.get("name") == name:
            every = max(30, cfg.every_sec)
            s["monitor"] = {
                "enabled": cfg.enabled, "every_sec": every,
                "whatsapp": cfg.whatsapp, "auto_trade": cfg.auto_trade,
            }
            _save_scanners(items)
            if not cfg.enabled:
                _monitor_state.pop(name, None)
            else:
                st = _monitor_state.setdefault(name, {})
                st["next_run"] = time.time()  # run immediately, then settle onto the clock boundary
            return {"ok": True}
    raise HTTPException(404, f"no saved scanner named '{name}'")


@app.get("/api/monitors")
async def get_monitors():
    out = []
    for s in _load_scanners():
        mon = s.get("monitor") or {}
        st = _monitor_state.get(s["name"], {})
        log_path = _monitor_log_path(s["name"])
        log_runs = 0
        if log_path.exists():
            try:
                log_runs = sum(1 for _ in log_path.open())
            except OSError:
                pass
        out.append({
            "name": s["name"],
            "enabled": bool(mon.get("enabled")),
            "every_sec": mon.get("every_sec", 300),
            "whatsapp": bool(mon.get("whatsapp")),
            "auto_trade": bool(mon.get("auto_trade")),
            "last_run": st.get("last_run"),
            "next_run": st.get("next_run"),
            "scanned": st.get("scanned"),
            "matched": st.get("matched"),
            "matches": st.get("matches", [])[:40],
            "error": st.get("error"),
            "log_runs": log_runs,
            "log_path": str(log_path.relative_to(ROOT)),
        })
    return {"monitors": out}


@app.get("/api/monitors/{name}/log")
async def get_monitor_log(name: str, limit: int = 200):
    """Recent runs from monitor_logs/<name>.jsonl, newest first — the durable, on-disk
    history behind the in-memory 'matches' the UI shows live (which only holds the latest run)."""
    path = _monitor_log_path(name)
    if not path.exists():
        return {"name": name, "path": str(path.relative_to(ROOT)), "total_runs": 0, "runs": []}
    lines = path.read_text().splitlines()
    total = len(lines)
    runs = [json.loads(l) for l in lines[-max(1, min(limit, 2000)):]]
    runs.reverse()
    return {"name": name, "path": str(path.relative_to(ROOT)), "total_runs": total, "runs": runs}


@app.get("/api/monitors/{name}/log.csv")
async def download_monitor_log_csv(name: str):
    """Every logged match across every run, flattened to one row per (run, symbol) —
    the full audit trail behind a monitor, for opening in a spreadsheet."""
    path = _monitor_log_path(name)
    if not path.exists():
        raise HTTPException(404, "no log yet for this monitor — enable it and wait for a run")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["run_time_ist", "run_time_epoch_ms", "symbol", "exchange", "last_price",
                      "change_24h_pct", "quote_volume_24h", "candle_close", "candle_volume",
                      "candle_time_epoch_ms", "new", "scanned", "matched", "error"])
    for line in path.read_text().splitlines():
        run = json.loads(line)
        ts = run["ts"]
        ts_ist = _dt.datetime.fromtimestamp((ts + IST_OFFSET_MS) / 1000, tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        matches = run.get("matches") or []
        if not matches:
            writer.writerow([ts_ist, ts, "", "", "", "", "", "", "", "", "", run.get("scanned", ""), run.get("matched", ""), run.get("error", "")])
        for m in matches:
            writer.writerow([ts_ist, ts, m.get("symbol"), m.get("exchange"), m.get("lastPrice"),
                              m.get("percentageChange"), m.get("quoteVolume"), m.get("candleClose"),
                              m.get("candleVolume"), m.get("candleTime"), m.get("new", False),
                              run.get("scanned", ""), run.get("matched", ""), run.get("error", "")])
    fname = _monitor_log_path(name).stem + "-log.csv"
    return Response(content=buf.getvalue(), media_type="text/csv",
                     headers={"Content-Disposition": f'attachment; filename="{fname}"'})


def _monitor_log_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "scanner"
    return MONITOR_LOG_DIR / f"{safe}.jsonl"


def _log_monitor_run(name: str, ts_ms: int, scanned: int, matched: int, matches: list[dict], error: Optional[str] = None):
    """Append one run's result to monitor_logs/<name>.jsonl (one JSON object per line) so
    every monitor run — hit or miss — is durably saved to disk for later review, not just
    held in the server's in-memory state. Rotates the oldest lines off once a file grows
    past MONITOR_LOG_MAX_RUNS runs."""
    path = _monitor_log_path(name)
    line = json.dumps({"ts": ts_ms, "scanned": scanned, "matched": matched, "matches": matches, "error": error})
    try:
        with path.open("a") as f:
            f.write(line + "\n")
        lines = path.read_text().splitlines()
        if len(lines) > MONITOR_LOG_MAX_RUNS:
            path.write_text("\n".join(lines[-MONITOR_LOG_MAX_RUNS:]) + "\n")
    except OSError as e:
        log.warning(f"monitor log write failed for {name!r}: {e}")


TERMUX_NOTIFY_BIN = shutil.which("termux-notification")
TERMUX_NOTIFY_ENABLED = os.getenv("TERMUX_NOTIFY", "1") != "0"


async def send_termux_notification(title: str, body: str, notif_id: str):
    """Fires a real Android notification via Termux:API, independent of any browser tab.
    No-ops silently when not running inside Termux (binary absent) so this is safe on any host."""
    if not TERMUX_NOTIFY_BIN or not TERMUX_NOTIFY_ENABLED:
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            TERMUX_NOTIFY_BIN, "-t", title, "-c", body, "-i", notif_id,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
    except Exception as e:
        log.warning(f"termux-notification failed: {e}")


# ------------------------------------------------------- auto-trading -------
#
# Pipeline per new match on an auto_trade-enabled monitor:
#   1. size the trade from TRADE_RISK_INR (converted to USDT via CoinSwitch's own live
#      USDT/INR spot ticker) and the signal candle's own low/high as the stop-loss
#   2. skip entirely if that size falls below the symbol's exchange minimum (never risk
#      more than asked)
#   3. skip if today's IST-day trade count or loss cap has been reached
#   4. LIVE_TRADING=0 (default): log + WhatsApp exactly what would have traded, no order calls
#      LIVE_TRADING=1: set leverage, place a MARKET entry, then reduce-only STOP_MARKET +
#      TAKE_PROFIT_MARKET orders sized to close the whole position. If either safety-net
#      order fails to place, immediately flatten the position at market rather than leave it
#      unprotected.
#   5. a background loop polls open positions; once one disappears (SL or TP filled), it
#      figures out which side closed it, cancels the dangling sibling order, updates the IST-day
#      loss tracker, and sends a closed-trade WhatsApp alert.

TRADES_FILE = ROOT / "trades.json"
MAX_TRADE_LOG = 2000


def _load_trades() -> list[dict]:
    if TRADES_FILE.exists():
        try:
            return json.loads(TRADES_FILE.read_text())
        except json.JSONDecodeError:
            return []
    return []


def _append_trade(rec: dict):
    items = _load_trades()
    items.append(rec)
    if len(items) > MAX_TRADE_LOG:
        items = items[-MAX_TRADE_LOG:]
    TRADES_FILE.write_text(json.dumps(items, indent=2))


def _update_trade(order_id: str, patch: dict):
    items = _load_trades()
    for t in items:
        if t.get("entry_order_id") == order_id:
            t.update(patch)
            break
    TRADES_FILE.write_text(json.dumps(items, indent=2))


@app.get("/api/trades")
async def list_trades(limit: int = 100):
    items = _load_trades()
    return {"trades": items[-limit:][::-1], "total": len(items)}


_instrument_info_cache: dict[str, tuple[float, dict]] = {}   # "EXCHANGE_2" -> (ts, {native_symbol: info})
INSTRUMENT_INFO_TTL = 3600.0   # instrument specs rarely change


async def get_instrument_info(native_symbol: str) -> Optional[dict]:
    hit = _instrument_info_cache.get(FUTURES_EXCHANGE_PARAM)
    now = time.time()
    if not hit or now - hit[0] > INSTRUMENT_INFO_TTL:
        data = await cs_get("/trade/api/v2/futures/instrument_info", {"exchange": FUTURES_EXCHANGE_PARAM})
        raw = data.get("data", data) or {}
        hit = (now, raw)
        _instrument_info_cache[FUTURES_EXCHANGE_PARAM] = hit
    return hit[1].get(native_symbol.upper())


_usdt_inr_cache: tuple[float, float] = (0.0, 0.0)   # (ts, rate)
USDT_INR_TTL = 60.0


async def get_usdt_inr_rate() -> float:
    """Live INR-per-USDT rate straight from CoinSwitch's own USDT/INR spot ticker — no external
    FX dependency, and it's the same rate CoinSwitch itself would give you converting INR->USDT."""
    global _usdt_inr_cache
    now = time.time()
    if now - _usdt_inr_cache[0] < USDT_INR_TTL and _usdt_inr_cache[1] > 0:
        return _usdt_inr_cache[1]
    tickers = await fetch_all_tickers("coinswitchx")
    t = tickers.get("USDT/INR")
    rate = float((t or {}).get("lastPrice", 0) or 0)
    if rate <= 0:
        raise HTTPException(502, "USDT/INR ticker unavailable")
    _usdt_inr_cache = (now, rate)
    return rate


def _round_step(value: float, step: float) -> float:
    if step <= 0:
        return value
    return math.floor(value / step + 1e-9) * step


async def set_leverage(native_symbol: str, leverage: int):
    await cs_post("/trade/api/v2/futures/leverage", {
        "exchange": FUTURES_EXCHANGE_PARAM, "symbol": native_symbol, "leverage": leverage,
    })


async def place_futures_order(native_symbol: str, side: str, order_type: str,
                               quantity: float = 0, price: Optional[float] = None,
                               trigger_price: Optional[float] = None,
                               reduce_only: bool = False) -> dict:
    body = {
        "exchange": FUTURES_EXCHANGE_PARAM, "symbol": native_symbol, "side": side,
        "order_type": order_type, "quantity": quantity, "reduce_only": reduce_only,
    }
    if price is not None:
        body["price"] = price
    if trigger_price is not None:
        body["trigger_price"] = trigger_price
    data = await cs_post("/trade/api/v2/futures/order", body)
    return data.get("data", data)


async def get_order_status(order_id: str) -> dict:
    data = await cs_get("/trade/api/v2/futures/order", {"order_id": order_id})
    return data.get("data", {}).get("order", data.get("data", {}))


async def cancel_order(order_id: str):
    try:
        await cs_delete("/trade/api/v2/futures/order", {"exchange": FUTURES_EXCHANGE_PARAM, "order_id": order_id})
    except HTTPException as e:
        log.warning("cancel_order(%s) failed (may already be filled/cancelled): %s", order_id, e.detail)


async def get_open_position(native_symbol: str) -> Optional[dict]:
    data = await cs_get("/trade/api/v2/futures/positions",
                         {"exchange": FUTURES_EXCHANGE_PARAM, "symbol": native_symbol})
    raw = data.get("data", data)
    if isinstance(raw, list):
        return raw[0] if raw else None
    if isinstance(raw, dict) and raw.get("symbol"):
        return raw
    return None


_trade_day_state = {"date": None, "count": 0, "loss_inr": 0.0}
_open_positions: dict[str, dict] = {}   # native_symbol -> tracking record


def _ist_today_str() -> str:
    ts_ist = _dt.datetime.fromtimestamp((time.time() * 1000 + IST_OFFSET_MS) / 1000, tz=_dt.timezone.utc)
    return ts_ist.strftime("%Y-%m-%d")


def _check_daily_cap() -> tuple[bool, str]:
    today = _ist_today_str()
    if _trade_day_state["date"] != today:
        _trade_day_state.update({"date": today, "count": 0, "loss_inr": 0.0})
    if _trade_day_state["count"] >= TRADE_MAX_PER_DAY:
        return False, f"daily trade cap reached ({TRADE_MAX_PER_DAY}/day)"
    if _trade_day_state["loss_inr"] >= TRADE_MAX_LOSS_INR_PER_DAY:
        return False, f"daily loss cap reached (₹{_trade_day_state['loss_inr']:.0f}/₹{TRADE_MAX_LOSS_INR_PER_DAY:.0f})"
    return True, ""


def _record_trade_opened():
    _check_daily_cap()   # ensures date rollover happened first
    _trade_day_state["count"] += 1


def _record_trade_loss(loss_inr: float):
    _check_daily_cap()
    if loss_inr > 0:
        _trade_day_state["loss_inr"] += loss_inr


async def execute_auto_trade(monitor_name: str, match: dict, direction: str = "long"):
    """Entry point called from the monitor loop for each newly-matched symbol on an
    auto_trade-enabled monitor. Never raises — a bad trade attempt shouldn't kill the monitor."""
    symbol = match["symbol"]
    native = fut_native_symbol(symbol)
    entry = float(match["candleClose"])
    sl = float(match["candleLow"]) if direction == "long" else float(match["candleHigh"])
    risk_per_unit = abs(entry - sl)
    trade_id = f"{monitor_name}-{symbol}-{int(time.time() * 1000)}"
    base_rec = {
        "trade_id": trade_id, "monitor": monitor_name, "symbol": symbol, "native_symbol": native,
        "direction": direction, "entry": entry, "sl": sl, "opened_at": int(time.time() * 1000),
        "leverage": TRADE_LEVERAGE, "risk_inr": TRADE_RISK_INR, "live": LIVE_TRADING,
    }

    if risk_per_unit <= 0:
        base_rec.update({"status": "skipped", "reason": "zero-width signal candle (entry == SL)"})
        _append_trade(base_rec)
        return

    target = entry + risk_per_unit * TRADE_TARGET_RR * (1 if direction == "long" else -1)
    base_rec["target"] = target

    ok, cap_reason = _check_daily_cap()
    if not ok:
        base_rec.update({"status": "skipped", "reason": cap_reason})
        _append_trade(base_rec)
        log.info("auto-trade skipped for %s: %s", symbol, cap_reason)
        return

    try:
        inr_rate = await get_usdt_inr_rate()
        risk_usdt = TRADE_RISK_INR / inr_rate
        info = await get_instrument_info(native)
        if not info:
            base_rec.update({"status": "error", "reason": f"no instrument_info for {native}"})
            _append_trade(base_rec)
            return
        step = float(info["base_quantity_step_size"])
        min_qty = float(info["min_base_quantity"])
        qty_precision = int(info.get("quantity_precision", 4))
        max_lev = float(info["max_leverage"])

        raw_qty = risk_usdt / risk_per_unit
        qty = round(_round_step(raw_qty, step), max(qty_precision, 0))
        base_rec.update({"risk_usdt": round(risk_usdt, 4), "usdt_inr_rate": inr_rate, "quantity": qty})

        if qty < min_qty:
            base_rec.update({
                "status": "skipped",
                "reason": f"₹{TRADE_RISK_INR:.0f} sizes to {qty} {native}, below exchange minimum {min_qty}",
            })
            _append_trade(base_rec)
            log.info("auto-trade skipped for %s: below exchange minimum (%.6g < %.6g)", symbol, qty, min_qty)
            return

        leverage = min(TRADE_LEVERAGE, int(max_lev))
        notional = qty * entry
        margin_usdt = notional / leverage
        base_rec.update({"leverage": leverage, "notional_usdt": round(notional, 4), "margin_usdt": round(margin_usdt, 4)})
    except HTTPException as e:
        base_rec.update({"status": "error", "reason": f"sizing failed: {e.detail}"})
        _append_trade(base_rec)
        log.warning("auto-trade sizing failed for %s: %s", symbol, e.detail)
        return

    entry_side = "BUY" if direction == "long" else "SELL"
    exit_side = "SELL" if direction == "long" else "BUY"

    if not LIVE_TRADING:
        base_rec.update({"status": "dry_run"})
        _append_trade(base_rec)
        asyncio.create_task(send_whatsapp_message(
            f"[DRY RUN] CoinSwitch Scanner — \"{monitor_name}\"\n{symbol} {direction.upper()}\n"
            f"Entry {entry:g}  SL {sl:g}  Target {target:g}\n"
            f"Qty {qty:g} ({leverage}x) — risk ₹{TRADE_RISK_INR:.0f} (~{risk_usdt:.2f} USDT)\n"
            f"No real order placed (LIVE_TRADING=0)."
        ))
        asyncio.create_task(send_termux_notification(
            f"[DRY RUN] {monitor_name} — {symbol}", f"{direction.upper()} entry {entry:g} SL {sl:g} tgt {target:g}",
            f"cs-trade-{symbol}",
        ))
        return

    # ---- LIVE from here on: real orders, real money ----
    try:
        await set_leverage(native, leverage)
        entry_order = await place_futures_order(native, entry_side, "MARKET", quantity=qty)
        entry_order_id = entry_order.get("order_id")
        base_rec.update({"status": "entry_placed", "entry_order_id": entry_order_id})
        _append_trade(base_rec)
        _record_trade_opened()
    except HTTPException as e:
        base_rec.update({"status": "error", "reason": f"entry order failed: {e.detail}"})
        _append_trade(base_rec)
        asyncio.create_task(send_whatsapp_message(
            f"CoinSwitch Scanner — \"{monitor_name}\"\n{symbol}: entry order FAILED: {e.detail}"
        ))
        return

    # confirm fill before placing SL/TP (a MARKET order should fill almost immediately)
    exec_qty, avg_price = 0.0, entry
    for _ in range(10):
        await asyncio.sleep(1.0)
        try:
            st = await get_order_status(entry_order_id)
        except HTTPException:
            continue
        exec_qty = float(st.get("exec_quantity", 0) or 0)
        if exec_qty > 0:
            avg_price = float(st.get("avg_execution_price", entry) or entry)
            break

    if exec_qty <= 0:
        _update_trade(entry_order_id, {"status": "error", "reason": "entry order did not fill within 10s"})
        asyncio.create_task(send_whatsapp_message(
            f"CoinSwitch Scanner — \"{monitor_name}\"\n{symbol}: entry order placed but not confirmed filled — check manually."
        ))
        return

    # Re-anchor SL/target to the ACTUAL fill price, not the (possibly stale-by-a-minute) signal
    # price computed before the order went in — same risk_per_unit distance, so the ₹ risk stays
    # exactly what was sized, regardless of how much price moved between signal and fill.
    sign = 1 if direction == "long" else -1
    sl = avg_price - risk_per_unit * sign
    target = avg_price + risk_per_unit * TRADE_TARGET_RR * sign

    sl_order_id = tp_order_id = None
    try:
        sl_order = await place_futures_order(native, exit_side, "STOP_MARKET", quantity=0,
                                              trigger_price=round(sl, 8), reduce_only=True)
        sl_order_id = sl_order.get("order_id")
        tp_order = await place_futures_order(native, exit_side, "TAKE_PROFIT_MARKET", quantity=0,
                                              trigger_price=round(target, 8), reduce_only=True)
        tp_order_id = tp_order.get("order_id")
    except HTTPException as e:
        log.error("SL/TP placement failed for %s, flattening immediately: %s", symbol, e.detail)
        try:
            await place_futures_order(native, exit_side, "MARKET", quantity=exec_qty, reduce_only=True)
            flatten_note = "position flattened immediately."
        except HTTPException as e2:
            flatten_note = f"FLATTEN ALSO FAILED — position may be unprotected: {e2.detail}. Close it manually now."
        if sl_order_id:
            await cancel_order(sl_order_id)
        if tp_order_id:
            await cancel_order(tp_order_id)
        _update_trade(entry_order_id, {"status": "error", "reason": f"SL/TP placement failed: {e.detail}; {flatten_note}"})
        asyncio.create_task(send_whatsapp_message(
            f"⚠️ CoinSwitch Scanner — \"{monitor_name}\"\n{symbol}: SL/TP order placement failed after entry filled.\n{flatten_note}"
        ))
        return

    _update_trade(entry_order_id, {
        "status": "open", "exec_quantity": exec_qty, "avg_execution_price": avg_price,
        "sl_order_id": sl_order_id, "tp_order_id": tp_order_id,
        "sl": sl, "target": target,   # re-anchored to actual fill, may differ from pre-fill signal values above
    })
    _open_positions[native] = {
        "trade_id": trade_id, "entry_order_id": entry_order_id, "monitor": monitor_name,
        "symbol": symbol, "direction": direction, "qty": exec_qty, "entry": avg_price,
        "sl": sl, "target": target, "sl_order_id": sl_order_id, "tp_order_id": tp_order_id,
    }
    asyncio.create_task(send_whatsapp_message(
        f"CoinSwitch Scanner — \"{monitor_name}\"\n{symbol} {direction.upper()} order placed\n"
        f"Entry {avg_price:g}  SL {sl:g}  Target {target:g}\nQty {exec_qty:g} ({leverage}x)"
    ))


async def _position_monitor_loop():
    """Polls every tracked open position; once CoinSwitch no longer reports it as open, the SL or
    TP reduce-only order filled and closed it — figure out which, cancel the dangling sibling,
    update the daily loss tracker, and send a closed-trade alert."""
    while True:
        try:
            for native, pos in list(_open_positions.items()):
                try:
                    live_pos = await get_open_position(native)
                except HTTPException:
                    continue
                if live_pos is not None:
                    continue   # still open, nothing to do this tick

                sl_status = tp_status = None
                try:
                    if pos.get("sl_order_id"):
                        sl_status = await get_order_status(pos["sl_order_id"])
                    if pos.get("tp_order_id"):
                        tp_status = await get_order_status(pos["tp_order_id"])
                except HTTPException:
                    pass

                sl_filled = sl_status and float(sl_status.get("exec_quantity", 0) or 0) > 0
                tp_filled = tp_status and float(tp_status.get("exec_quantity", 0) or 0) > 0

                if sl_filled and pos.get("tp_order_id"):
                    await cancel_order(pos["tp_order_id"])
                elif tp_filled and pos.get("sl_order_id"):
                    await cancel_order(pos["sl_order_id"])

                exit_price = None
                if sl_filled:
                    exit_price = float(sl_status.get("avg_execution_price", pos["sl"]) or pos["sl"])
                elif tp_filled:
                    exit_price = float(tp_status.get("avg_execution_price", pos["target"]) or pos["target"])
                sign = 1 if pos["direction"] == "long" else -1
                pnl_usdt = None
                if exit_price is not None:
                    pnl_usdt = (exit_price - pos["entry"]) * sign * pos["qty"]

                pnl_inr = None
                if pnl_usdt is not None:
                    try:
                        inr_rate = await get_usdt_inr_rate()
                        pnl_inr = pnl_usdt * inr_rate
                    except HTTPException:
                        pass
                    if pnl_inr is not None and pnl_inr < 0:
                        _record_trade_loss(-pnl_inr)

                outcome = "win" if (pnl_usdt or 0) > 0 else ("loss" if (pnl_usdt or 0) < 0 else "flat")
                _update_trade(pos["entry_order_id"], {
                    "status": f"closed_{outcome}", "closed_at": int(time.time() * 1000),
                    "exit_price": exit_price, "pnl_usdt": pnl_usdt, "pnl_inr": pnl_inr,
                })
                asyncio.create_task(send_whatsapp_message(
                    f"CoinSwitch Scanner — \"{pos['monitor']}\"\n{pos['symbol']} closed: {outcome.upper()}\n"
                    f"Exit {exit_price:g}" + (f"  PnL ₹{pnl_inr:.0f}" if pnl_inr is not None else "")
                ))
                _open_positions.pop(native, None)
        except Exception:
            log.exception("position monitor loop error")
        await asyncio.sleep(15)


async def _monitor_loop():
    while True:
        try:
            for s in _load_scanners():
                mon = s.get("monitor") or {}
                if not mon.get("enabled"):
                    continue
                name = s["name"]
                every = max(30, int(mon.get("every_sec", 300)))
                st = _monitor_state.setdefault(name, {})
                if "next_run" not in st:
                    st["next_run"] = _next_aligned_run(every)
                if time.time() < st["next_run"]:
                    continue
                run_ts = time.time()
                try:
                    res = await run_scan(ScanRequest(**s["config"]))
                    prev = {m["symbol"] for m in st.get("matches", [])}
                    new_syms = [m["symbol"] for m in res["matches"] if m["symbol"] not in prev]
                    for m in res["matches"]:
                        m["new"] = m["symbol"] in new_syms
                    st.update({
                        "last_run": run_ts, "scanned": res["scanned"],
                        "matched": res["matched"], "matches": res["matches"], "error": None,
                    })
                    _log_monitor_run(name, int(run_ts * 1000), res["scanned"], res["matched"], res["matches"])
                    if mon.get("whatsapp") and new_syms:
                        asyncio.create_task(send_whatsapp_message(
                            f"CoinSwitch Scanner — \"{name}\"\n{len(new_syms)} new match(es): "
                            + ", ".join(new_syms[:20])
                        ))
                    if new_syms:
                        asyncio.create_task(send_termux_notification(
                            f"CoinSwitch Scanner — {name}",
                            f"{len(new_syms)} new match(es): " + ", ".join(new_syms[:20]),
                            f"cs-monitor-{name}",
                        ))
                    if mon.get("auto_trade") and new_syms:
                        new_set = set(new_syms)
                        for m in res["matches"]:
                            if m["symbol"] in new_set:
                                asyncio.create_task(execute_auto_trade(name, m, direction="long"))
                except Exception as e:  # keep the loop alive whatever happens
                    err = str(e)[:200]
                    st.update({"last_run": run_ts,
                              "matches": st.get("matches", []),
                              "error": err})
                    _log_monitor_run(name, int(run_ts * 1000), 0, 0, [], error=err)
                st["next_run"] = _next_aligned_run(every)
        except Exception:
            pass
        await asyncio.sleep(1)


async def _warm_cache_once():
    """Pre-fetch candles for every saved scanner's universe right after startup, so the first
    manual run of the day hits a warm cache instead of paying the full upstream rate-limit cost
    cold. Best-effort — a failed/slow scanner here never blocks the server or another scanner."""
    try:
        scanners = _load_scanners()
        if not scanners:
            return
        spot_sem = asyncio.Semaphore(SPOT_CANDLE_CONCURRENCY)
        fut_sem = asyncio.Semaphore(FUT_CANDLE_CONCURRENCY)
        seen: set[tuple] = set()

        async def warm_one(sym_exch: str, sym: str, interval: int, n_candles: int):
            key = (sym_exch, sym, interval, n_candles)
            if key in seen:
                return
            seen.add(key)
            sem = fut_sem if sym_exch == "futures" else spot_sem
            async with sem:
                try:
                    await fetch_candles(sym_exch, sym, interval, n_candles, ttl=CANDLE_CACHE_TTL)
                except Exception:
                    pass

        for s in scanners:
            cfg = s.get("config") or {}
            try:
                if cfg.get("scan_mode") == "history":
                    req = HistoryScanRequest(**cfg)
                    _, n_candles, _ = history_scan_sizing(req)
                else:
                    req = ScanRequest(**cfg)
                    n_candles = required_lookback(req.conditions, req.interval)
            except Exception:
                continue
            if not req.conditions:
                continue
            merged, universe = await resolve_universe(req)
            await asyncio.gather(*(
                warm_one(merged.get(sym, ("c2c1", {}))[0], sym, req.interval, n_candles)
                for sym in universe
            ))
        log.info("cache warm-up done: %d saved scanner(s), %d unique candle series pre-fetched",
                  len(scanners), len(seen))
    except Exception as e:
        log.warning("cache warm-up failed: %s", e)


@app.on_event("startup")
async def _start_monitors():
    asyncio.create_task(_monitor_loop())
    asyncio.create_task(_warm_cache_once())
    asyncio.create_task(_position_monitor_loop())


@app.on_event("shutdown")
async def _shutdown():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


# ------------------------------------------------- saved scanners -----------
#
# GitHub-backed persistence: _gh_synced_files tracks which paths have already had their one
# startup pull from GitHub (success, "not found", or failure — any outcome counts), so a hot loop
# like _monitor_loop (ticks every 1s and calls _load_scanners each time) only ever costs one GitHub
# API call per process lifetime instead of one per tick. Every save still pushes to GitHub
# immediately (low frequency, user-triggered) and updates the local file so the next read anywhere
# in this process sees it instantly without a round trip.

_gh_sha_cache: dict[str, Optional[str]] = {}
_gh_synced_files: set[str] = set()


def _gh_client() -> httpx.Client:
    return httpx.Client(
        base_url="https://api.github.com",
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10.0,
    )


def _gh_pull(path: str) -> Optional[list]:
    """One-shot fetch of a JSON file from the repo. None if missing/failed — caller falls back to
    the local on-disk copy either way, so a GitHub outage never blocks reads."""
    try:
        with _gh_client() as c:
            r = c.get(f"/repos/{GITHUB_REPO}/contents/{path}", params={"ref": GITHUB_BRANCH})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        body = r.json()
        _gh_sha_cache[path] = body["sha"]
        return json.loads(base64.b64decode(body["content"]).decode("utf-8"))
    except Exception as e:
        log.warning("GitHub read failed for %s: %s", path, e)
        return None


def _gh_push(path: str, data) -> None:
    """Best-effort write-through to the repo. Failures are logged, never raised — the local file
    write already happened, so a save never fails just because GitHub is unreachable."""
    payload = {
        "message": f"Update {path}",
        "content": base64.b64encode(json.dumps(data, indent=2).encode("utf-8")).decode("ascii"),
        "branch": GITHUB_BRANCH,
    }
    sha = _gh_sha_cache.get(path)
    if sha:
        payload["sha"] = sha
    try:
        with _gh_client() as c:
            r = c.put(f"/repos/{GITHUB_REPO}/contents/{path}", json=payload)
        r.raise_for_status()
        _gh_sha_cache[path] = r.json()["content"]["sha"]
    except Exception as e:
        log.warning("GitHub write failed for %s: %s", path, e)


def _load_json_file(file: Path, gh_path: str) -> list[dict]:
    if GITHUB_CONFIGURED and gh_path not in _gh_synced_files:
        _gh_synced_files.add(gh_path)
        data = _gh_pull(gh_path)
        if data is not None:
            file.write_text(json.dumps(data, indent=2))
    if file.exists():
        try:
            return json.loads(file.read_text())
        except json.JSONDecodeError:
            return []
    return []


def _save_json_file(file: Path, gh_path: str, data) -> None:
    file.write_text(json.dumps(data, indent=2))
    if GITHUB_CONFIGURED:
        _gh_synced_files.add(gh_path)  # a push makes this process's copy authoritative either way
        _gh_push(gh_path, data)


def _load_scanners() -> list[dict]:
    return _load_json_file(SCANNERS_FILE, "scanners.json")


def _save_scanners(items: list[dict]):
    _save_json_file(SCANNERS_FILE, "scanners.json", items)


def _load_trash() -> list[dict]:
    return _load_json_file(SCANNERS_TRASH_FILE, "scanners_trash.json")


def _save_trash(items: list[dict]):
    _save_json_file(SCANNERS_TRASH_FILE, "scanners_trash.json", items[-MAX_TRASH:])


class SavedScanner(BaseModel):
    name: str
    config: dict


@app.get("/api/scanners")
async def list_scanners():
    return {"scanners": _load_scanners()}


@app.post("/api/scanners")
async def save_scanner(item: SavedScanner):
    items = [s for s in _load_scanners() if s.get("name") != item.name]
    items.append({"name": item.name, "config": item.config, "saved_at": int(time.time() * 1000)})
    _save_scanners(items)
    return {"ok": True, "count": len(items)}


@app.delete("/api/scanners/{name}")
async def delete_scanner(name: str):
    """Soft delete — the scanner moves to scanners_trash.json (capped at MAX_TRASH) instead of
    vanishing, so an accidental delete can be undone via POST /api/scanners/trash/{name}/restore."""
    items = _load_scanners()
    victim = next((s for s in items if s.get("name") == name), None)
    new = [s for s in items if s.get("name") != name]
    _save_scanners(new)
    if victim is not None:
        trash = _load_trash()
        victim = dict(victim)
        victim["deleted_at"] = int(time.time() * 1000)
        trash.append(victim)
        _save_trash(trash)
    return {"ok": True, "deleted": len(items) - len(new)}


@app.get("/api/scanners/trash")
async def list_trash():
    return {"trash": _load_trash()}


@app.post("/api/scanners/trash/{name}/restore")
async def restore_scanner(name: str):
    trash = _load_trash()
    idx = next((i for i, s in enumerate(trash) if s.get("name") == name), None)
    if idx is None:
        raise HTTPException(404, f"'{name}' not found in trash")
    item = trash.pop(idx)
    item.pop("deleted_at", None)
    items = _load_scanners()
    existing = {s.get("name") for s in items}
    restored_name = item["name"]
    if restored_name in existing:
        n = 2
        while f"{restored_name} (restored {n})" in existing:
            n += 1
        restored_name = f"{restored_name} (restored {n})"
        item["name"] = restored_name
    items.append(item)
    _save_scanners(items)
    _save_trash(trash)
    return {"ok": True, "name": restored_name}


@app.delete("/api/scanners/trash/{name}")
async def purge_trash(name: str):
    trash = _load_trash()
    new = [s for s in trash if s.get("name") != name]
    _save_trash(new)
    return {"ok": True, "deleted": len(trash) - len(new)}


# --------------------------------------------------------------- static -----

REACT_DIR = ROOT / "static_react"

app.mount("/assets", StaticFiles(directory=REACT_DIR / "assets"), name="react-assets")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/")
async def index():
    return FileResponse(REACT_DIR / "index.html")


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    # Client-side routes (e.g. /backtest) get the SPA shell; anything under
    # /api, /static, /assets should have matched a real route/mount above.
    if full_path.startswith(("api/", "static/", "assets/")):
        raise HTTPException(404)
    # Root-level public files (favicon.svg, notification-icon.png, etc.) — Vite copies
    # everything from frontend/public/ to static_react/'s root at build time, so serve
    # them for real instead of silently handing back index.html for a PNG request.
    if full_path:
        candidate = (REACT_DIR / full_path).resolve()
        if candidate.is_file() and REACT_DIR.resolve() in candidate.parents:
            return FileResponse(candidate)
    return FileResponse(REACT_DIR / "index.html")
