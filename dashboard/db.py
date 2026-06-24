import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


_pool: Optional[ConnectionPool] = None


# build the postgres connection string from the same env vars the c++ collector uses
def _dsn() -> str:

    host: str = os.environ.get("POSTGRES_HOST", "localhost")
    port: str = os.environ.get("POSTGRES_PORT", "5432")
    user: str = os.environ.get("POSTGRES_USER", "nodemonitor")
    password: str = os.environ.get("POSTGRES_PASSWORD", "devpass")
    db: str = os.environ.get("POSTGRES_DB", "node_monitor")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


# initialise the module-level pool the first time anyone asks for a connection
def _get_pool() -> ConnectionPool:

    global _pool
    if _pool is None:
        _pool = ConnectionPool(conninfo=_dsn(), min_size=2, max_size=8, kwargs={"row_factory": dict_row})
        _pool.wait()
    return _pool


# borrow a connection for the duration of a with-block; it's returned to the pool automatically on exit
@contextmanager
def connection() -> Iterator[psycopg.Connection]:

    pool = _get_pool()
    with pool.connection() as conn:
        yield conn


# run a query and return all rows as a list of dicts; cheap helper for routes that just need a list back
def query_all(sql: str, params: Optional[tuple] = None) -> list[dict[str, Any]]:

    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()


# run a query and return the single row (or None); used for summary endpoints
def query_one(sql: str, params: Optional[tuple] = None) -> Optional[dict[str, Any]]:

    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchone()
