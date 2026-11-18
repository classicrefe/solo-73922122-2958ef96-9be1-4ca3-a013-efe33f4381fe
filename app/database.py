"""SQLite 持久化层。

- cells：导入的调查格值（导入后不可更换，无更新/删除接口）。
- publications：已获准公开的汇总记录（不可撤销，只插入，无更新/删除接口）。
  receipt/prev_receipt 两列为发布回执签发链：旧记录（升级前已存在）
  两列为 NULL，即「未签」，不能当作已核验。

所有写操作均在单事务中完成：失败即整体回滚，不会留下半次发布。
发布记录与其回执在同一事务落库（BEGIN IMMEDIATE）：事务内先读前一
回执摘要、插入记录、计算并写回回执，再整体提交；任一步失败全部回滚，
不留单边结果。BEGIN IMMEDIATE 在事务开始即取写锁，多进程/多窗口并发
发布时，回执链顺序与落库顺序一致。

连接按操作创建，启用 WAL，重启后数据保留在 DB_PATH 指定的库文件中。
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "app.db"
DB_PATH = os.environ.get("DB_PATH", str(_DEFAULT_DB))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cells (
    district   TEXT NOT NULL,
    age_group  TEXT NOT NULL,
    population INTEGER NOT NULL CHECK (population >= 5),
    detected   INTEGER NOT NULL CHECK (detected >= 0 AND detected <= population),
    PRIMARY KEY (district, age_group)
);
CREATE TABLE IF NOT EXISTS publications (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    districts    TEXT NOT NULL,          -- JSON 数组
    age_groups   TEXT NOT NULL,          -- JSON 数组
    total        INTEGER NOT NULL CHECK (total >= 0),
    created_at   TEXT NOT NULL,          -- ISO8601 UTC
    prev_receipt TEXT,                   -- 前一已签记录的回执；链首为 ''；未签旧记录为 NULL
    receipt      TEXT                    -- 本记录回执 HMAC；未签旧记录为 NULL
);
"""


def connect() -> sqlite3.Connection:
    path = DB_PATH
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with closing(connect()) as conn, conn:
        conn.executescript(_SCHEMA)
        # 旧库迁移：补上回执列，既有记录保持 NULL（未签）。
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(publications)")}
        if "prev_receipt" not in cols:
            conn.execute("ALTER TABLE publications ADD COLUMN prev_receipt TEXT")
        if "receipt" not in cols:
            conn.execute("ALTER TABLE publications ADD COLUMN receipt TEXT")


def get_cells() -> list[dict]:
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT district, age_group, population, detected FROM cells "
            "ORDER BY district, age_group"
        ).fetchall()
    return [dict(r) for r in rows]


def insert_cells(rows: list[dict]) -> None:
    """单事务写入全部格值；任一失败则整体回滚。组合重复抛 IntegrityError。"""
    with closing(connect()) as conn, conn:
        conn.executemany(
            "INSERT INTO cells (district, age_group, population, detected) "
            "VALUES (:district, :age_group, :population, :detected)",
            rows,
        )


def _row_to_pub(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["districts"] = json.loads(d["districts"])
    d["age_groups"] = json.loads(d["age_groups"])
    d["signed"] = d["receipt"] is not None
    return d


def get_publications() -> list[dict]:
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT id, districts, age_groups, total, created_at, prev_receipt, receipt "
            "FROM publications ORDER BY id"
        ).fetchall()
    return [_row_to_pub(r) for r in rows]


def get_publication(pid: int) -> dict | None:
    with closing(connect()) as conn:
        r = conn.execute(
            "SELECT id, districts, age_groups, total, created_at, prev_receipt, receipt "
            "FROM publications WHERE id = ?",
            (pid,),
        ).fetchone()
    return _row_to_pub(r) if r else None


def has_signed_records() -> bool:
    """库内是否已存在已签记录（用于密钥丢失时的明确失败判定）。"""
    with closing(connect()) as conn:
        r = conn.execute(
            "SELECT 1 FROM publications WHERE receipt IS NOT NULL LIMIT 1"
        ).fetchone()
    return r is not None


def insert_publication(
    districts: list[str], age_groups: list[str], total: int, key: bytes
) -> dict:
    """单事务插入一条公开记录并签发回执；失败回滚，不留单边结果。

    事务（BEGIN IMMEDIATE）内依次：读前一已签回执 → 插入记录 → 按记录
    实际 id 计算回执 → 写回回执 → 提交。任一步失败整体回滚；写锁自事务
    开始持有，故并发发布的回执链顺序与落库顺序一致。
    """
    # 延迟导入，避免 database ↔ receipts 循环依赖。
    from .receipts import GENESIS_PREV, compute_receipt

    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    districts, age_groups = list(districts), list(age_groups)
    with closing(connect()) as conn:
        conn.isolation_level = None  # 手动管理事务
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT receipt FROM publications WHERE receipt IS NOT NULL "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev = row["receipt"] if row else GENESIS_PREV
            cur = conn.execute(
                "INSERT INTO publications "
                "(districts, age_groups, total, created_at, prev_receipt, receipt) "
                "VALUES (?, ?, ?, ?, ?, NULL)",
                (
                    json.dumps(districts, ensure_ascii=False),
                    json.dumps(age_groups, ensure_ascii=False),
                    int(total),
                    created,
                    prev,
                ),
            )
            pid = cur.lastrowid
            receipt = compute_receipt(
                key, pid, districts, age_groups, int(total), created, prev
            )
            conn.execute("UPDATE publications SET receipt = ? WHERE id = ?", (receipt, pid))
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass  # 连接已不可用时回滚失败不掩盖原始异常
            raise
    return {
        "id": pid,
        "districts": districts,
        "age_groups": age_groups,
        "total": int(total),
        "created_at": created,
        "prev_receipt": prev,
        "receipt": receipt,
        "signed": True,
    }
