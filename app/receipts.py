"""发布回执：HMAC 签发链与核验。

每次发布用本地密钥对「发布ID、所选范围、总数、发布时间、前一回执摘要」
计算 HMAC-SHA256，形成回执；各回执经 prev_receipt 串联成签发链。
外部复核者留存回执后，可在公开页粘贴核验：逐条对照签发链与库内记录，
报告首处缺失、篡改或断链（末条被删也不会误判通过）。

密钥管理：
- 首次启动生成 32 字节随机密钥，以十六进制文本保存在数据库之外的
  密钥文件（默认与库文件同目录的 receipt.key，权限 0600），重启沿用；
- 密钥文件丢失且库内已存在已签记录时，load_or_create_key 抛出
  KeyLostError，应用明确启动失败（重新生成会让全部历史回执失效，
  静默换钥等于让篡改者获得重签能力，故必须显式失败）。

防篡改边界：核验针对「密钥与用户手中回执未泄露」的数据库改写。
攻击者能改库但算不出合法 HMAC，因此改记录、改回执、断链、删末条
都会被核验发现；旧发布记录（receipt 为 NULL）标为未签，不参与链，
不能当成已核验。
"""

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from .database import DB_PATH

RECEIPT_VERSION = 1
GENESIS_PREV = ""  # 链首记录的「前一回执摘要」

KEY_PATH = os.environ.get(
    "RECEIPT_KEY_PATH",
    # 默认放在库文件旁（数据库之外的独立文件）；:memory: 时退到 ./receipt.key
    str(Path(DB_PATH).resolve().parent / "receipt.key")
    if DB_PATH != ":memory:"
    else str(Path("receipt.key").resolve()),
)

_KEY_LEN = 32  # 字节


class KeyLostError(RuntimeError):
    """密钥丢失且库内存在已签记录：必须明确失败，不得静默重建。"""


class KeyFormatError(RuntimeError):
    """密钥文件内容损坏（非合法十六进制或长度不足）。"""


# ---------------- 密钥 ----------------


def load_or_create_key(key_path: str | None = None, has_signed_records: bool | None = None) -> bytes:
    """加载密钥文件；不存在时视情况生成或明确失败。

    key_path:           密钥文件路径（默认 KEY_PATH）。
    has_signed_records: 库内是否已有已签记录（默认 None，调用方须显式给出，
                        以免误把「未检查」当成「无已签记录」）。
    """
    if has_signed_records is None:
        raise ValueError("has_signed_records 必须显式给出")
    path = Path(key_path or KEY_PATH)
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            raise KeyFormatError(f"回执密钥文件内容损坏（非十六进制）：{path}")
        if len(key) < _KEY_LEN:
            raise KeyFormatError(f"回执密钥文件长度过短（{len(key)} 字节）：{path}")
        return key
    if has_signed_records:
        raise KeyLostError(
            f"回执密钥文件丢失（{path}），且库中已存在已签发布记录。"
            "已签记录无法在没有原密钥的情况下核验，重新生成密钥会使全部历史回执"
            "失效并掩盖可能的篡改，因此拒绝启动。请从备份恢复密钥文件后重启。"
        )
    key = secrets.token_bytes(_KEY_LEN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.hex(), encoding="utf-8")
    os.chmod(path, 0o600)
    return key


# ---------------- 回执计算 ----------------


def _canonical_message(
    pid: int,
    districts: list[str],
    age_groups: list[str],
    total: int,
    created_at: str,
    prev_receipt: str,
) -> bytes:
    """HMAC 输入的规范序列化（键排序、紧凑分隔符，保证可复算）。"""
    payload = {
        "v": RECEIPT_VERSION,
        "id": int(pid),
        "districts": list(districts),
        "age_groups": list(age_groups),
        "total": int(total),
        "created_at": str(created_at),
        "prev": str(prev_receipt),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def compute_receipt(
    key: bytes,
    pid: int,
    districts: list[str],
    age_groups: list[str],
    total: int,
    created_at: str,
    prev_receipt: str,
) -> str:
    """对发布记录计算回执 HMAC-SHA256（十六进制）。"""
    msg = _canonical_message(pid, districts, age_groups, total, created_at, prev_receipt)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def build_receipt_doc(pub: dict) -> dict:
    """由已签发布记录构造可供下载/留存的回执文档。"""
    return {
        "version": RECEIPT_VERSION,
        "publication_id": pub["id"],
        "districts": list(pub["districts"]),
        "age_groups": list(pub["age_groups"]),
        "total": pub["total"],
        "created_at": pub["created_at"],
        "prev_receipt": pub["prev_receipt"],
        "receipt": pub["receipt"],
    }


# ---------------- 核验 ----------------


def _fail(kind: str, message: str, steps: list[dict], pid: int | None = None) -> dict:
    failure = {"kind": kind, "message": message}
    if pid is not None:
        failure["publication_id"] = pid
    return {"ok": False, "failure": failure, "steps": steps}


def _check_doc_shape(doc) -> str | None:
    """校验回执文档结构；合法返回 None，否则返回错误描述。"""
    if not isinstance(doc, dict):
        return "回执须为 JSON 对象"
    required = {
        "version",
        "publication_id",
        "districts",
        "age_groups",
        "total",
        "created_at",
        "prev_receipt",
        "receipt",
    }
    missing = required - set(doc)
    if missing:
        return f"回执缺少字段：{sorted(missing)}"
    if doc["version"] != RECEIPT_VERSION:
        return f"不支持的回执版本：{doc['version']!r}"
    if not isinstance(doc["publication_id"], int) or doc["publication_id"] < 1:
        return "publication_id 须为正整数"
    for f in ("districts", "age_groups"):
        if not isinstance(doc[f], list) or not all(isinstance(x, str) for x in doc[f]):
            return f"{f} 须为字符串数组"
    if not isinstance(doc["total"], int) or doc["total"] < 0:
        return "total 须为非负整数"
    if not isinstance(doc["created_at"], str):
        return "created_at 须为字符串"
    if not isinstance(doc["prev_receipt"], str):
        return "prev_receipt 须为字符串"
    r = doc["receipt"]
    if not isinstance(r, str) or len(r) != 64 or any(c not in "0123456789abcdef" for c in r):
        return "receipt 须为 64 位十六进制字符串"
    return None


def verify_receipt(doc, key: bytes, publications: list[dict]) -> dict:
    """核验一份回执：逐条对照签发链与库内记录。

    doc:          用户粘贴的回执文档（已解析为 dict）。
    key:          本地回执密钥。
    publications: 库内全部发布记录（按 id 升序，含 receipt/prev_receipt/signed）。
    返回 {"ok": bool, "failure": {...}|None, "steps": [...]}，
    失败时报告首处（id 最小处）缺失/篡改/断链。
    """
    steps: list[dict] = []

    err = _check_doc_shape(doc)
    if err:
        return _fail("invalid_receipt_doc", f"回执格式无效：{err}", steps)

    doc_id = doc["publication_id"]

    # 1) 回执自身须通过密钥核验（防伪造/防涂改回执本身）。
    expect = compute_receipt(
        key,
        doc_id,
        doc["districts"],
        doc["age_groups"],
        doc["total"],
        doc["created_at"],
        doc["prev_receipt"],
    )
    if not hmac.compare_digest(expect, doc["receipt"]):
        return _fail(
            "receipt_auth_failed",
            "回执未通过密钥核验：回执内容被涂改，或并非本台签发。",
            steps,
            doc_id,
        )

    # 2) 沿签发链从链首走到回执所指记录，逐条重算 HMAC 并检查前向链接，
    #    报告首处（id 最小处）问题。未签旧记录不参与链。
    signed = [p for p in publications if p.get("signed")]
    prev = GENESIS_PREV
    for p in signed:
        if p["id"] > doc_id:
            break
        if p["prev_receipt"] != prev:
            return _fail(
                "broken_chain",
                f"签发链在第 #{p['id']} 条断裂：其前一回执摘要与前一已签记录的回执不符，"
                "中间记录可能被删除或改动。",
                steps,
                p["id"],
            )
        recomputed = compute_receipt(
            key,
            p["id"],
            p["districts"],
            p["age_groups"],
            p["total"],
            p["created_at"],
            p["prev_receipt"],
        )
        if not hmac.compare_digest(recomputed, p["receipt"]):
            return _fail(
                "tampered",
                f"第 #{p['id']} 条库内记录被改动：按库内内容重算的回执与库内所存回执不符。",
                steps,
                p["id"],
            )
        steps.append({"publication_id": p["id"], "status": "ok"})
        prev = p["receipt"]

    # 3) 回执所指记录本身须在库中且与回执一致（末条被删在此暴露，不会误判通过）。
    rec = next((p for p in publications if p["id"] == doc_id), None)
    if rec is None:
        return _fail(
            "missing",
            f"库中不存在第 #{doc_id} 条发布记录：该记录（含末条情形）已被删除。",
            steps,
            doc_id,
        )
    if not rec.get("signed"):
        return _fail(
            "unsigned",
            f"第 #{doc_id} 条是未签旧记录，不能当作已核验。",
            steps,
            doc_id,
        )
    for f, dv in (
        ("districts", doc["districts"]),
        ("age_groups", doc["age_groups"]),
        ("total", doc["total"]),
        ("created_at", doc["created_at"]),
        ("prev_receipt", doc["prev_receipt"]),
    ):
        if rec[f] != dv:
            return _fail(
                "tampered",
                f"第 #{doc_id} 条库内记录的字段 {f} 与所持回执不符：库内记录被改动。",
                steps,
                doc_id,
            )
    if not hmac.compare_digest(rec["receipt"], doc["receipt"]):
        return _fail(
            "tampered",
            f"第 #{doc_id} 条库内所存回执与所持回执不一致：库内回执被改动。",
            steps,
            doc_id,
        )

    return {
        "ok": True,
        "failure": None,
        "steps": steps,
        "verified_publication_id": doc_id,
        "chain_length": len(steps),
    }
