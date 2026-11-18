"""关键功能自测：以 TestClient 驱动应用，使用独立临时数据库与临时密钥。

运行：python tests/selftest.py
覆盖：导入校验、导入后不可更换、预览、安全/不安全发布、
两窗口各自安全但合并不安全的重核拒绝、公开页不泄露格内检出数、
公开记录落盘持久化、保存失败不留半次发布、求解器并发安全、
发布回执签发链（下载、核验、篡改/删末条/删中间/断链/伪造回执）、
未签旧记录处理、旧库迁移、密钥生成/沿用/丢失明确失败、
回执与记录同事务落库、并发写回执链顺序一致、重启沿用。
"""

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TMP = tempfile.mkdtemp(prefix="cdc_guard_test_")
os.environ["DB_PATH"] = str(Path(_TMP) / "test.db")  # 须在导入 app 前设置

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

SAMPLE = (
    "分区,年龄组,人数,检出数\n"
    "城东,青年,10,2\n"
    "城东,老年,10,8\n"
    "城西,青年,10,8\n"
    "城西,老年,10,8\n"
)

results = []


def check(name, cond, extra=""):
    results.append(bool(cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond and extra:
        print("       " + extra.replace("\n", "\n       ")[:800])


def run():
    with TestClient(app) as client:
        def import_csv(text):
            return client.post(
                "/api/import",
                files={"file": ("data.csv", text.encode("utf-8"), "text/csv")},
            )

        # ---- 1. 导入校验 ----
        r = import_csv("分区,年龄组,人数,检出数\nA,青,4,1\n")
        check("人数<5 被拒绝", r.status_code == 400, r.text)
        r = import_csv("分区,年龄组,人数,检出数\nA,青,10,11\n")
        check("检出数>人数 被拒绝", r.status_code == 400, r.text)
        r = import_csv("分区,年龄组,人数,检出数\nA,青,10,-1\n")
        check("检出数<0 被拒绝", r.status_code == 400, r.text)
        r = import_csv("分区,年龄组,人数,检出数\nA,青,10,1.5\n")
        check("检出数非整数 被拒绝", r.status_code == 400, r.text)
        r = import_csv("分区,年龄组,人数,检出数\nA,青,10,1\nA,青,10,2\n")
        check("组合重复 被拒绝", r.status_code == 400, r.text)
        many = "分区,年龄组,人数,检出数\n" + "\n".join(
            f"区{i},青,10,1" for i in range(17)
        )
        r = import_csv(many)
        check("超过16格 被拒绝", r.status_code == 400, r.text)
        r = import_csv("分区,年龄组,人数\nA,青,10\n")
        check("缺少检出数列 被拒绝", r.status_code == 400, r.text)

        # ---- 2. 正常导入 + 不可更换 ----
        r = import_csv(SAMPLE)
        check("示例导入成功", r.status_code == 201 and r.json()["imported"] == 4, r.text)
        r = import_csv(SAMPLE)
        check("重复导入被拒绝（导入后不可更换）", r.status_code == 409, r.text)

        # ---- 3. 预览 ----
        r = client.post("/api/preview", json={"districts": ["城东"], "age_groups": ["青年", "老年"]})
        j = r.json()
        check("预览「城东」总数=10 且安全",
              r.status_code == 200 and j["total"] == 10 and j["safe"], r.text)

        # ---- 4. 两窗口各自安全、合并不安全 ----
        r = client.post("/api/preview", json={"districts": ["城东", "城西"], "age_groups": ["老年"]})
        j = r.json()
        check("窗口「老年」单独预览安全（总数=16）",
              r.status_code == 200 and j["total"] == 16 and j["safe"], r.text)

        r = client.post("/api/publish", json={"districts": ["城东"], "age_groups": ["青年", "老年"]})
        check("发布「城东」成功（总数=10）",
              r.status_code == 201 and r.json()["total"] == 10, r.text)

        r = client.post("/api/preview", json={"districts": ["城东", "城西"], "age_groups": ["老年"]})
        j = r.json()
        aff = j.get("affected", [])
        check("合并后预览「老年」不安全", r.status_code == 200 and not j["safe"], r.text)
        check("受影响格为 城东/青年，可行范围[0,4]，不可取≥5",
              len(aff) == 1
              and aff[0]["district"] == "城东" and aff[0]["age_group"] == "青年"
              and aff[0]["min"] == 0 and aff[0]["max"] == 4
              and aff[0]["zero_feasible"] and not aff[0]["ge5_feasible"], r.text)

        r = client.post("/api/publish", json={"districts": ["城东", "城西"], "age_groups": ["老年"]})
        check("确认发布「老年」被按最新公开记录重核拒绝(409)", r.status_code == 409, r.text)
        d = r.json().get("detail", {})
        check("409 响应含受影响格与可行范围",
              isinstance(d, dict) and d.get("affected")
              and d["affected"][0]["max"] == 4, r.text)

        # ---- 5. 与已公开记录合并仍安全的发布可继续 ----
        r = client.post("/api/publish", json={"districts": ["城东", "城西"], "age_groups": ["青年"]})
        check("发布「青年」（与「城东」合并仍安全）成功",
              r.status_code == 201 and r.json()["total"] == 10, r.text)
        r = client.post("/api/publish", json={"districts": ["城东", "城西"], "age_groups": ["老年"]})
        check("「老年」仍被拒绝", r.status_code == 409, r.text)

        # ---- 6. 公开页不泄露格内检出数 ----
        r = client.get("/api/public")
        j = r.json()
        check("公开 API 不含 detected 字段",
              r.status_code == 200 and all("detected" not in c for c in j["cells"]), r.text)
        check("公开 API 含人数与 2 条获准汇总",
              len(j["cells"]) == 4 and all("population" in c for c in j["cells"])
              and len(j["publications"]) == 2, r.text)
        check("公开汇总不含格值字段",
              all(set(p) == {"id", "districts", "age_groups", "total", "created_at",
                             "prev_receipt", "receipt", "signed"}
                  for p in j["publications"]), r.text)
        r = client.get("/public")
        check("公开页可访问", r.status_code == 200 and "公开" in r.text)
        r = client.get("/")
        check("内部审查台可访问", r.status_code == 200 and "审查台" in r.text)

        # ---- 7. 持久化（直接读库文件，等价于重启后再读） ----
        conn = sqlite3.connect(os.environ["DB_PATH"])
        n_pub = conn.execute("SELECT COUNT(*) FROM publications").fetchone()[0]
        n_cell = conn.execute("SELECT COUNT(*) FROM cells").fetchone()[0]
        conn.close()
        check("公开记录与格值已落盘（重启保留）", n_pub == 2 and n_cell == 4)

        # ---- 8. 其他边界 ----
        r = client.post("/api/preview", json={"districts": ["不存在"], "age_groups": ["青年"]})
        check("未知分区被拒绝", r.status_code == 400, r.text)
        r = client.post("/api/publish", json={"districts": [], "age_groups": ["青年"]})
        check("空选择被拒绝", r.status_code == 400, r.text)
        r = client.post("/api/preview", json={"districts": ["城东"], "age_groups": []})
        check("空年龄组被拒绝", r.status_code == 400, r.text)

        # ---- 9. 保存失败不留半次发布 ----
        import app.database as dbmod
        import app.main as mainmod

        before = len(client.get("/api/public").json()["publications"])

        # 9a. 接口层：插入时发生异常 → 500 且无记录产生
        orig_insert = mainmod.insert_publication
        def _boom(*a, **k):
            raise RuntimeError("模拟保存失败")
        mainmod.insert_publication = _boom
        try:
            r = client.post(
                "/api/publish",
                json={"districts": ["城东", "城西"], "age_groups": ["青年"]},
            )
            check("保存时异常返回 500", r.status_code == 500, r.text)
        finally:
            mainmod.insert_publication = orig_insert
        after = len(client.get("/api/public").json()["publications"])
        check("保存失败未留下半次发布", after == before, f"before={before} after={after}")

        # 9b. 存储层：库不可打开时写入抛错，且库内容不变
        orig_path = dbmod.DB_PATH
        dbmod.DB_PATH = _TMP  # 指向目录：SQLite 无法打开
        try:
            dbmod.insert_publication(["x"], ["y"], 1, b"k" * 32)
            check("库不可打开时写入抛错", False, "未抛错")
        except Exception:
            check("库不可打开时写入抛错", True)
        finally:
            dbmod.DB_PATH = orig_path
        after = len(client.get("/api/public").json()["publications"])
        check("库写失败后记录数不变", after == before, f"before={before} after={after}")

        # ---- 10. 求解器并发安全（z3 每评估独立 Context） ----
        from concurrent.futures import ThreadPoolExecutor

        from app.solver import evaluate

        cells = dbmod.get_cells()
        pubs = dbmod.get_publications()
        cand = {"districts": ["城东", "城西"], "age_groups": ["老年"], "total": 16}
        with ThreadPoolExecutor(max_workers=8) as ex:
            outs = list(ex.map(lambda _: evaluate(cells, pubs, cand), range(40)))
        check(
            "40 路并发求解结果一致且正确",
            all(
                (not o["safe"])
                and len(o["affected"]) == 1
                and o["affected"][0]["max"] == 4
                for o in outs
            ),
            str(outs[:2]),
        )

        # ================= 发布回执签发链 =================
        from app import receipts

        # ---- 11. 发布即签发回执，链式衔接 ----
        pubs = dbmod.get_publications()
        p1, p2 = pubs[0], pubs[1]
        check("发布记录含回执且标记已签",
              p1["signed"] and p2["signed"]
              and len(p1["receipt"]) == 64 and len(p2["receipt"]) == 64, str(pubs))
        check("链首前一回执摘要为空（GENESIS）", p1["prev_receipt"] == receipts.GENESIS_PREV)
        check("第 2 条前一回执摘要 == 第 1 条回执", p2["prev_receipt"] == p1["receipt"])

        # ---- 12. 回执下载与核验通过 ----
        r = client.get("/api/receipt/2")
        check("下载回执成功", r.status_code == 200, r.text)
        doc2 = r.json()
        check("回执文档字段齐全",
              set(doc2) == {"version", "publication_id", "districts", "age_groups",
                            "total", "created_at", "prev_receipt", "receipt"}
              and doc2["publication_id"] == 2, json.dumps(doc2, ensure_ascii=False))
        check("回执下载头为附件", "attachment" in r.headers.get("content-disposition", ""))
        r = client.get("/api/receipt/999")
        check("下载不存在记录的回执返回 404", r.status_code == 404, r.text)
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc2)})
        j = r.json()
        check("真实回执核验通过",
              j.get("ok") is True and j.get("verified_publication_id") == 2
              and j.get("chain_length") == 2, json.dumps(j, ensure_ascii=False))

        # ---- 13. 第三条发布（城西×老年，安全），得到 3 条已签记录 ----
        r = client.post("/api/publish", json={"districts": ["城西"], "age_groups": ["老年"]})
        check("发布「城西/老年」（总数=8）成功",
              r.status_code == 201 and r.json()["total"] == 8, r.text)
        doc3 = client.get("/api/receipt/3").json()
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        check("3 条链上记录核验通过", r.json().get("ok") is True, r.text)

        # ---- 14. 库内记录被篡改：核验报告首处篡改 ----
        conn = sqlite3.connect(os.environ["DB_PATH"])
        conn.execute("UPDATE publications SET total = 999 WHERE id = 1")
        conn.commit(); conn.close()
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        j = r.json()
        check("库内第 1 条被改 → 核验报告首处篡改为 #1",
              j.get("ok") is False and j["failure"]["kind"] == "tampered"
              and j["failure"]["publication_id"] == 1, json.dumps(j, ensure_ascii=False))
        conn = sqlite3.connect(os.environ["DB_PATH"])
        conn.execute("UPDATE publications SET total = 10 WHERE id = 1")
        conn.commit(); conn.close()
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        check("恢复后核验重新通过", r.json().get("ok") is True, r.text)

        # ---- 15. 删除中间记录：签发链断裂 ----
        saved2 = dbmod.get_publication(2)
        conn = sqlite3.connect(os.environ["DB_PATH"])
        conn.execute("DELETE FROM publications WHERE id = 2")
        conn.commit(); conn.close()
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        j = r.json()
        check("删除中间第 2 条 → 核验报告断链（#3）",
              j.get("ok") is False and j["failure"]["kind"] == "broken_chain"
              and j["failure"]["publication_id"] == 3, json.dumps(j, ensure_ascii=False))
        conn = sqlite3.connect(os.environ["DB_PATH"])
        conn.execute(
            "INSERT INTO publications (id, districts, age_groups, total, created_at, "
            "prev_receipt, receipt) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (saved2["id"], json.dumps(saved2["districts"], ensure_ascii=False),
             json.dumps(saved2["age_groups"], ensure_ascii=False), saved2["total"],
             saved2["created_at"], saved2["prev_receipt"], saved2["receipt"]),
        )
        conn.commit(); conn.close()
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        check("恢复中间记录后核验重新通过", r.json().get("ok") is True, r.text)

        # ---- 16. 删除末条记录：不能误判通过 ----
        saved3 = dbmod.get_publication(3)
        conn = sqlite3.connect(os.environ["DB_PATH"])
        conn.execute("DELETE FROM publications WHERE id = 3")
        conn.commit(); conn.close()
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        j = r.json()
        check("删除末条第 3 条 → 核验报告缺失而非通过",
              j.get("ok") is False and j["failure"]["kind"] == "missing"
              and j["failure"]["publication_id"] == 3, json.dumps(j, ensure_ascii=False))
        conn = sqlite3.connect(os.environ["DB_PATH"])
        conn.execute(
            "INSERT INTO publications (id, districts, age_groups, total, created_at, "
            "prev_receipt, receipt) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (saved3["id"], json.dumps(saved3["districts"], ensure_ascii=False),
             json.dumps(saved3["age_groups"], ensure_ascii=False), saved3["total"],
             saved3["created_at"], saved3["prev_receipt"], saved3["receipt"]),
        )
        conn.commit(); conn.close()
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        check("恢复末条后核验重新通过", r.json().get("ok") is True, r.text)

        # ---- 17. 伪造/涂改回执与格式错误 ----
        forged = dict(doc3, total=999)  # 涂改回执内容，回执值不变
        r = client.post("/api/verify", json={"receipt_text": json.dumps(forged)})
        j = r.json()
        check("涂改回执内容 → 未通过密钥核验",
              j.get("ok") is False and j["failure"]["kind"] == "receipt_auth_failed",
              json.dumps(j, ensure_ascii=False))
        forged2 = dict(doc3, receipt="0" * 64)
        r = client.post("/api/verify", json={"receipt_text": json.dumps(forged2)})
        check("替换回执值 → 未通过密钥核验",
              r.json().get("ok") is False
              and r.json()["failure"]["kind"] == "receipt_auth_failed", r.text)
        r = client.post("/api/verify", json={"receipt_text": "这不是JSON"})
        check("非 JSON 回执 → 格式无效",
              r.json().get("ok") is False
              and r.json()["failure"]["kind"] == "invalid_receipt_doc", r.text)
        bad = dict(doc3); del bad["receipt"]
        r = client.post("/api/verify", json={"receipt_text": json.dumps(bad)})
        check("缺字段回执 → 格式无效",
              r.json().get("ok") is False
              and r.json()["failure"]["kind"] == "invalid_receipt_doc", r.text)
        # 用真密钥为「不存在的 id 999」造一份结构上合法的回执 → 缺失
        ghost = {
            "version": 1, "publication_id": 999, "districts": ["城东"],
            "age_groups": ["青年"], "total": 1,
            "created_at": "2030-01-01T00:00:00+00:00", "prev_receipt": "",
        }
        ghost["receipt"] = receipts.compute_receipt(
            mainmod.app.state.receipt_key, 999, ["城东"], ["青年"], 1,
            "2030-01-01T00:00:00+00:00", "",
        )
        r = client.post("/api/verify", json={"receipt_text": json.dumps(ghost)})
        j = r.json()
        check("指向不存在记录的有效回执 → 缺失",
              j.get("ok") is False and j["failure"]["kind"] == "missing"
              and j["failure"]["publication_id"] == 999, json.dumps(j, ensure_ascii=False))

        # ---- 18. 回执与发布记录同事务落库：回执计算失败不留单边结果 ----
        before = dbmod.get_publications()
        orig_compute = receipts.compute_receipt
        def _boom_receipt(*a, **k):
            raise RuntimeError("模拟回执计算失败")
        receipts.compute_receipt = _boom_receipt
        try:
            r = client.post("/api/publish",
                            json={"districts": ["城西"], "age_groups": ["老年"]})
            check("回执计算失败时发布返回 500", r.status_code == 500, r.text)
        finally:
            receipts.compute_receipt = orig_compute
        after = dbmod.get_publications()
        check("回执失败不留单边发布记录",
              len(after) == len(before)
              and all(p["signed"] for p in after), f"before={len(before)} after={len(after)}")
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        check("回执失败后签发链仍完整", r.json().get("ok") is True, r.text)

        # ---- 19. 未签旧记录：标为未签，不能当成已核验 ----
        conn = sqlite3.connect(os.environ["DB_PATH"])
        cur = conn.execute(
            "INSERT INTO publications (districts, age_groups, total, created_at) "
            "VALUES ('[\"旧区\"]', '[\"老年\"]', 7, '2020-01-01T00:00:00+00:00')"
        )
        legacy_id = cur.lastrowid
        conn.commit(); conn.close()
        j = client.get("/api/public").json()
        legacy = next(p for p in j["publications"] if p["id"] == legacy_id)
        check("旧记录在公开 API 标为未签",
              legacy["signed"] is False and legacy["receipt"] is None, json.dumps(legacy))
        r = client.get(f"/api/receipt/{legacy_id}")
        check("未签旧记录无回执可下载（409）", r.status_code == 409, r.text)
        # 即便持有真密钥、为其内容造出「自洽」回执，核验也不得判过
        legacy_doc = {
            "version": 1, "publication_id": legacy_id, "districts": ["旧区"],
            "age_groups": ["老年"], "total": 7,
            "created_at": "2020-01-01T00:00:00+00:00", "prev_receipt": "",
        }
        legacy_doc["receipt"] = receipts.compute_receipt(
            mainmod.app.state.receipt_key, legacy_id, ["旧区"], ["老年"], 7,
            "2020-01-01T00:00:00+00:00", "",
        )
        r = client.post("/api/verify", json={"receipt_text": json.dumps(legacy_doc)})
        j = r.json()
        check("未签旧记录核验不得判过（unsigned）",
              j.get("ok") is False and j["failure"]["kind"] == "unsigned",
              json.dumps(j, ensure_ascii=False))
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        check("未签旧记录不影响既有签发链核验", r.json().get("ok") is True, r.text)

        # ---- 20. 旧库迁移：既有记录自动补列并标为未签 ----
        tmp2 = tempfile.mkdtemp(prefix="cdc_guard_migrate_")
        db2 = str(Path(tmp2) / "old.db")
        conn = sqlite3.connect(db2)
        conn.execute(
            "CREATE TABLE publications ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, districts TEXT NOT NULL, "
            "age_groups TEXT NOT NULL, total INTEGER NOT NULL CHECK (total >= 0), "
            "created_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO publications (districts, age_groups, total, created_at) "
            "VALUES ('[\"A\"]', '[\"B\"]', 5, '2020-01-01T00:00:00+00:00')"
        )
        conn.commit(); conn.close()
        orig_path = dbmod.DB_PATH
        dbmod.DB_PATH = db2
        try:
            dbmod.init_db()  # 触发迁移
            migrated = dbmod.get_publications()
            check("旧库迁移后既有记录标为未签",
                  len(migrated) == 1 and migrated[0]["signed"] is False
                  and migrated[0]["receipt"] is None
                  and migrated[0]["prev_receipt"] is None, str(migrated))
            check("迁移库无已签记录（has_signed_records=False）",
                  dbmod.has_signed_records() is False)
        finally:
            dbmod.DB_PATH = orig_path

        # ---- 21. 密钥管理：生成、沿用、丢失明确失败 ----
        tmpk = tempfile.mkdtemp(prefix="cdc_guard_key_")
        kp = str(Path(tmpk) / "receipt.key")
        k1 = receipts.load_or_create_key(kp, has_signed_records=False)
        check("首次启动生成 32 字节密钥", len(k1) == 32)
        check("密钥文件权限为 0600",
              (os.stat(kp).st_mode & 0o777) == 0o600, oct(os.stat(kp).st_mode))
        k2 = receipts.load_or_create_key(kp, has_signed_records=True)
        check("重启沿用同一密钥（即使有已签记录，文件在即用）", k1 == k2)
        os.remove(kp)
        try:
            receipts.load_or_create_key(kp, has_signed_records=True)
            check("密钥丢失且有已签记录 → 明确失败", False, "未抛错")
        except receipts.KeyLostError as e:
            check("密钥丢失且有已签记录 → 明确失败", "密钥" in str(e), str(e))
        k3 = receipts.load_or_create_key(kp, has_signed_records=False)
        check("无已签记录时密钥丢失可重新生成", len(k3) == 32 and k3 != k1)
        Path(kp).write_text("zzzz-not-hex", encoding="utf-8")
        try:
            receipts.load_or_create_key(kp, has_signed_records=False)
            check("密钥文件损坏 → 明确失败", False, "未抛错")
        except receipts.KeyFormatError:
            check("密钥文件损坏 → 明确失败", True)
        check("密钥保存在数据库之外",
              receipts.KEY_PATH != dbmod.DB_PATH
              and Path(receipts.KEY_PATH).is_file()
              and Path(receipts.KEY_PATH).name != Path(dbmod.DB_PATH).name)
        conn = sqlite3.connect(os.environ["DB_PATH"])
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        check("库内不存密钥（无密钥表）", tables <= {"cells", "publications", "sqlite_sequence"},
              str(tables))

        # ---- 22. 并发写：回执顺序与落库顺序一致 ----
        key = mainmod.app.state.receipt_key
        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(lambda i: dbmod.insert_publication(["并发区"], ["组"], i, key),
                        range(12)))
        pubs = dbmod.get_publications()
        prev, chain_ok = receipts.GENESIS_PREV, True
        for p in pubs:
            if not p["signed"]:
                continue  # 未签旧记录不参与链
            if p["prev_receipt"] != prev:
                chain_ok = False
                break
            prev = p["receipt"]
        check("12 路并发写入后回执链顺序与落库顺序一致", chain_ok,
              json.dumps([(p["id"], p["prev_receipt"], p["receipt"])
                          for p in pubs if p["signed"]], ensure_ascii=False)[:600])
        check("并发写入全部落库",
              len([p for p in pubs if p["signed"]]) == 3 + 12)

        # ---- 23. 重启沿用：同库同密钥，历史回执仍可核验 ----
        key_again = receipts.load_or_create_key(
            has_signed_records=dbmod.has_signed_records())
        check("重启沿用同一密钥", key_again == mainmod.app.state.receipt_key)
        r = client.post("/api/verify", json={"receipt_text": json.dumps(doc3)})
        check("重启后历史回执仍可核验", r.json().get("ok") is True, r.text)


run()
print(f"\n{sum(results)}/{len(results)} 通过")
sys.exit(0 if all(results) else 1)
