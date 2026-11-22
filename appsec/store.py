import hashlib
import json
import sqlite3
from contextlib import closing


def encoded(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


class SQLiteStore:
    def __init__(self, path):
        self.path = path
        with closing(self.connect()) as db, db:
            db.execute("""create table if not exists records (
                namespace text, key text, value text, primary key(namespace, key))""")
            db.execute("""create table if not exists audit (
                id integer primary key, timestamp text default current_timestamp,
                namespace text, key text, value text)""")

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def get(self, namespace, key):
        return self.all(namespace, key).get(key)

    def all(self, namespace, key=None):
        with closing(self.connect()) as db:
            rows = db.execute("select key,value from records where namespace=?"
                              " and (? is null or key=?) order by key", (namespace, key, key))
            return {key: json.loads(value) for key, value in rows}

    def put(self, namespace, key, value):
        body = encoded(value)
        with closing(self.connect()) as db, db:
            change = db.execute("""insert into records values (?,?,?)
                on conflict(namespace,key) do update set value=excluded.value
                where records.value!=excluded.value""", (namespace, key, body))
            if change.rowcount:
                db.execute("insert into audit(namespace,key,value) values (?,?,?)", (namespace, key, body))

    def event(self, namespace, key, value):
        with closing(self.connect()) as db, db:
            db.execute("insert into audit(namespace,key,value) values (?,?,?)",
                       (namespace, key, encoded(value)))

    def agent_metrics(self):
        with closing(self.connect()) as db:
            records = [json.loads(row[0]) for row in db.execute(
                "select value from audit where namespace='agent-execution'")]
        return {
            "agent_requests_total": sum(item["attempts"] for item in records),
            "agent_errors_total": sum(item["outcome"] != "completed" for item in records),
            "input_tokens_total": sum(item["input_tokens"] for item in records),
            "output_tokens_total": sum(item["output_tokens"] for item in records),
            "estimated_cost_total": round(sum(item["estimated_cost"] for item in records), 6),
        }
