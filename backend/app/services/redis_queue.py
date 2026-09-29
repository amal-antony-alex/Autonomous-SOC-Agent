import json
import os

import redis


class RedisInvestigationQueue:

    def __init__(self):
        self.redis_url = os.getenv(
            "REDIS_URL",
            "redis://redis:6379/0"
        )

        self.queue_name = os.getenv(
            "REDIS_QUEUE_NAME",
            "soc_investigation_queue"
        )

        self.client = redis.Redis.from_url(
            self.redis_url,
            decode_responses=True
        )

    def ping(self):
        return self.client.ping()

    def enqueue(self, task):
        self.client.rpush(
            self.queue_name,
            json.dumps(task)
        )

    def dequeue(self, timeout=5):
        try:
            result = self.client.blpop(
                self.queue_name,
                timeout=timeout
            )
        except redis.exceptions.TimeoutError:
            return None

        if result is None:
            return None

        _, payload = result

        return json.loads(payload)

    def size(self):
        return self.client.llen(
            self.queue_name
        )


redis_queue = RedisInvestigationQueue()
