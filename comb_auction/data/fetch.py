#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
from fractions import Fraction
from os import getenv
from typing import Any, Dict, List

from decimal import Decimal
from datetime import date, datetime

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

try:
    from dotenv import load_dotenv 

    load_dotenv()
except Exception:
    pass


NMAX = 120
TMAX = 10
PAIRMAX = 10


def _require_env(name: str) -> str:
    v = getenv(name, "")
    if not v:
        raise SystemExit(
            f"Missing env var {name}. Export it, or install python-dotenv and set it in .env."
        )
    return v


def _hex_addr(raw: bytes) -> str:
    return "0x" + raw.hex()


def _hex_uid(raw: bytes) -> str:
    return "0x" + raw.hex()


def compute_score_native(
    *,
    limit_sell: int,
    limit_buy: int,
    exec_sell: int,
    exec_buy: int,
    kind: str,  # must be "sell" or "buy"
    buy_token_price_e18: int,  # price in e18 (as stored in auction_prices)
) -> int:
    """
    Mirrors your Python scoring logic AND circuit math.

    Sell:
      partial_limit_buy = ceil(limit_buy * exec_sell / limit_sell)
      surplus_buy = exec_buy - partial_limit_buy
      score_native = floor(surplus_buy * buy_price)

    Buy:
      partial_limit_sell = floor(limit_sell * exec_buy / limit_buy)
      surplus_sell = partial_limit_sell - exec_sell
      score_native = floor(surplus_sell * (limit_buy/limit_sell) * buy_price)

    Where buy_price = buy_token_price_e18 / 1e18.
    """
    buy_price = Fraction(buy_token_price_e18, 10**18)

    if kind == "sell":
        partial_limit_buy = math.ceil(Fraction(limit_buy * exec_sell, limit_sell))
        surplus_buy = exec_buy - partial_limit_buy
        if surplus_buy <= 0:
            return 0
        return math.floor(Fraction(surplus_buy) * buy_price)

    if kind == "buy":
        partial_limit_sell = math.floor(Fraction(limit_sell * exec_buy, limit_buy))
        surplus_sell = partial_limit_sell - exec_sell
        if surplus_sell <= 0:
            return 0
        return math.floor(Fraction(surplus_sell) * Fraction(limit_buy, limit_sell) * buy_price)

    raise ValueError(f"Unexpected kind={kind!r}. Expected 'sell' or 'buy'.")


def kind_to_side(kind: str) -> int:
    """
    Circuit convention:
      0 = Sell
      1 = Buy
    """
    if kind == "sell":
        return 0
    if kind == "buy":
        return 1
    raise ValueError(f"Unexpected orders.kind={kind!r}. Expected 'sell' or 'buy'.")


def _row_to_jsonable(r: Any) -> Dict[str, Any]:
    """
    Convert a SQLAlchemy Row into a JSON-serializable dict.
    - bytes -> 0xhex
    - Decimal -> str (no precision loss)
    - datetime/date -> ISO string
    """
    d = dict(r._mapping)  # type: ignore[attr-defined]
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, (bytes, bytearray)):
            out[k] = "0x" + bytes(v).hex()
        elif isinstance(v, Decimal):
            out[k] = str(v)
        elif isinstance(v, (datetime, date)):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


SQL_RANGE = """
WITH trade_data AS (
    SELECT
        ps.auction_id,
        ps.uid                      AS solution_uid,
        ps.solver                   AS solver,
        pte.order_uid               AS order_uid,

        o.sell_token                AS sell_token,
        o.buy_token                 AS buy_token,
        o.sell_amount               AS limit_sell_amount,
        o.buy_amount                AS limit_buy_amount,
        o.kind                      AS order_kind,

        pte.executed_sell           AS executed_sell_amount,
        pte.executed_buy            AS executed_buy_amount

    FROM proposed_solutions ps
    LEFT JOIN proposed_trade_executions pte
           ON ps.auction_id = pte.auction_id AND ps.uid = pte.solution_uid
    LEFT JOIN orders o
           ON pte.order_uid = o.uid
    WHERE ps.auction_id BETWEEN :start_id AND :end_id
),
trade_data_with_prices AS (
    SELECT
        td.*,
        ap_buy.price AS buy_token_price_e18
    FROM trade_data td
    JOIN auction_prices ap_buy
      ON td.auction_id = ap_buy.auction_id AND td.buy_token = ap_buy.token
)
SELECT *
FROM trade_data_with_prices
ORDER BY auction_id ASC, solution_uid ASC;
"""

SQL_ONE_AUCTION_RAW = """
WITH trade_data AS (
    SELECT
        ps.auction_id,
        ps.uid                      AS solution_uid,
        ps.solver                   AS solver,
        pte.order_uid               AS order_uid,

        o.sell_token                AS sell_token,
        o.buy_token                 AS buy_token,
        o.sell_amount               AS limit_sell_amount,
        o.buy_amount                AS limit_buy_amount,
        o.kind                      AS order_kind,

        pte.executed_sell           AS executed_sell_amount,
        pte.executed_buy            AS executed_buy_amount

    FROM proposed_solutions ps
    LEFT JOIN proposed_trade_executions pte
           ON ps.auction_id = pte.auction_id AND ps.uid = pte.solution_uid
    LEFT JOIN orders o
           ON pte.order_uid = o.uid
    WHERE ps.auction_id = :auction_id
),
trade_data_with_prices AS (
    SELECT
        td.*,
        ap_buy.price AS buy_token_price_e18
    FROM trade_data td
    JOIN auction_prices ap_buy
      ON td.auction_id = ap_buy.auction_id AND td.buy_token = ap_buy.token
)
SELECT *
FROM trade_data_with_prices
ORDER BY auction_id ASC, solution_uid ASC;
"""


def fetch_auctions_circuit_json(session: Session, start_id: int, end_id: int) -> Dict[str, Any]:
    rows = session.execute(text(SQL_RANGE), {"start_id": start_id, "end_id": end_id}).fetchall()

    # Group rows by auction
    by_auction: Dict[int, List[Any]] = {}
    for r in rows:
        aid = int(r.auction_id)
        by_auction.setdefault(aid, []).append(r)

    auctions_out: List[Dict[str, Any]] = []
    skipped_auctions: List[Dict[str, Any]] = []
    skipped_solutions: List[Dict[str, Any]] = []

    for auction_id in sorted(by_auction.keys()):
        auction_rows = by_auction[auction_id]

        has_null_kind = any(r.order_kind is None for r in auction_rows if r.order_uid is not None)
        if has_null_kind:
            skipped_auctions.append(
                {
                    "auction_id": auction_id,
                    "reason": "orders.kind was NULL for at least one trade row; skipping auction",
                }
            )
            continue

        solutions_map: Dict[int, Dict[str, Any]] = {}

        for r in auction_rows:
            if r.order_uid is None:
                continue

            sol_uid = int(r.solution_uid)
            solver = _hex_addr(r.solver)
            solutions_map.setdefault(sol_uid, {"solution_uid": sol_uid, "solver": solver, "trades": []})

            kind = str(r.order_kind)
            side = kind_to_side(kind)

            sell_token = _hex_addr(r.sell_token)
            buy_token = _hex_addr(r.buy_token)

            limit_sell = int(r.limit_sell_amount)
            limit_buy = int(r.limit_buy_amount)
            exec_sell = int(r.executed_sell_amount)
            exec_buy = int(r.executed_buy_amount)

            buy_price_e18 = int(r.buy_token_price_e18)

            score_native = compute_score_native(
                limit_sell=limit_sell,
                limit_buy=limit_buy,
                exec_sell=exec_sell,
                exec_buy=exec_buy,
                kind=kind,
                buy_token_price_e18=buy_price_e18,
            )

            trade_obj = {
                "order_uid": _hex_uid(r.order_uid),
                "sell_token": sell_token,
                "buy_token": buy_token,
                "limit_sell": str(limit_sell),
                "limit_buy": str(limit_buy),
                "exec_sell": str(exec_sell),
                "exec_buy": str(exec_buy),
                "side": side,
                "buy_token_price_e18": str(buy_price_e18),
                "score_native": str(score_native),
            }

            trades = solutions_map[sol_uid]["trades"]
            if len(trades) < TMAX + 1:
                trades.append(trade_obj)
            # else: ignore extra rows, overflow already known

        filtered_solutions: List[Dict[str, Any]] = []
        for sol_uid in sorted(solutions_map.keys()):
            sol = solutions_map[sol_uid]
            if len(sol["trades"]) > TMAX:
                skipped_solutions.append(
                    {
                        "auction_id": auction_id,
                        "solution_uid": sol_uid,
                        "reason": f"trades_exceeded_TMAX ({len(sol['trades'])} > {TMAX})",
                    }
                )
                continue
            filtered_solutions.append(sol)

        if len(filtered_solutions) > NMAX:
            skipped_auctions.append(
                {
                    "auction_id": auction_id,
                    "reason": f"solutions_exceeded_NMAX ({len(filtered_solutions)} > {NMAX})",
                }
            )
            continue

        auctions_out.append(
            {
                "auction_id": auction_id,
                "caps": {"NMAX": NMAX, "TMAX": TMAX, "PAIRMAX": PAIRMAX},
                "solutions": filtered_solutions,
            }
        )

    return {
        "range": {"auction_start": start_id, "auction_end": end_id},
        "caps": {"NMAX": NMAX, "TMAX": TMAX, "PAIRMAX": PAIRMAX},
        "auctions": auctions_out,
        "skipped_auctions": skipped_auctions,
        "skipped_solutions": skipped_solutions,
    }


def fetch_one_auction_raw(session: Session, auction_id: int) -> Dict[str, Any]:
    rows = session.execute(text(SQL_ONE_AUCTION_RAW), {"auction_id": auction_id}).fetchall()
    return {
        "auction_id": auction_id,
        "rows": [_row_to_jsonable(r) for r in rows],
        "count": len(rows),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--auction_start", type=int, required=True)
    ap.add_argument("--auction_end", type=int, required=True)
    ap.add_argument("--auction_index", type=int, required=True) 
    args = ap.parse_args()

    db_url = _require_env("PROD_DB_URL")
    engine = create_engine("postgresql+psycopg://" + db_url, echo=False)

    with Session(engine) as session:
        out = fetch_auctions_circuit_json(session, args.auction_start, args.auction_end)
        full_path = f"auctions_{args.auction_start}_{args.auction_end}.json"
        with open(full_path, "w") as f:
            json.dump(out, f, indent=2)

        exported_auctions = out["auctions"]
        if args.auction_index < 0 or args.auction_index >= len(exported_auctions):
            raise SystemExit(
                f"auction_index {args.auction_index} out of bounds "
                f"(0..{len(exported_auctions)-1})"
            )
        selected_auction_id = int(exported_auctions[args.auction_index]["auction_id"])

        raw = fetch_one_auction_raw(session, selected_auction_id)
        raw_path = f"auction_{selected_auction_id}.json"
        with open(raw_path, "w") as f:
            json.dump(raw, f, indent=2)

    print(f"Wrote {full_path}")
    print(f"Auctions exported: {len(out['auctions'])}")
    print(f"Auctions skipped:  {len(out['skipped_auctions'])}")
    print(f"Solutions skipped (TMAX overflow): {len(out['skipped_solutions'])}")
    print(f"auction_index={args.auction_index} -> auction_id={selected_auction_id}")
    print(f"Wrote {raw_path} (rows={raw['count']})")

    if out["skipped_auctions"]:
        print("First skipped auctions:")
        for a in out["skipped_auctions"][:10]:
            print(f"  auction_id={a['auction_id']} reason={a['reason']}")
        if len(out["skipped_auctions"]) > 10:
            print(f"  ... and {len(out['skipped_auctions']) - 10} more")

    if out["skipped_solutions"]:
        print("First skipped solutions:")
        for s in out["skipped_solutions"][:10]:
            print(
                f"  auction_id={s['auction_id']} solution_uid={s['solution_uid']} reason={s['reason']}"
            )
        if len(out["skipped_solutions"]) > 10:
            print(f"  ... and {len(out['skipped_solutions']) - 10} more")


if __name__ == "__main__":
    main()
