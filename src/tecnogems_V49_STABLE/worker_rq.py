"""RQ worker entry point.

Run alongside gunicorn:
    rq worker tecnogems_orders --url $REDIS_URL
or:
    python worker_rq.py
"""

import os
import logging
from redis import Redis
from rq import Queue, Worker

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        raise SystemExit("REDIS_URL is not set — cannot start RQ worker")
    conn = Redis.from_url(redis_url)
    queues = [Queue("tecnogems_orders", connection=conn)]
    Worker(queues, connection=conn).work()
