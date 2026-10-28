
import json
import os

import redis


class RedisInvestigationQueue:
    def __init__(self):
        self.redis_url = os.getenv(
            "REDIS_URL",
            "redis://redis:6379/0",
        )
        self.queue_name = os.getenv(
            "REDIS_QUEUE_NAME",
            "soc_investigation_queue",
        )
        self.processing_queue_name = (
            f"{self.queue_name}:processing"
        )

        self.client = redis.Redis.from_url(
            self.redis_url,
            decode_responses=True,
        )

    @staticmethod
    def _serialize(task):
        # Keep the task's dictionary field order stable across
        # enqueue, reserve, acknowledgement, and release.
        return json.dumps(task)

    def ping(self):
        return self.client.ping()

    def enqueue(self, task):
        self.client.rpush(
            self.queue_name,
            self._serialize(task),
        )

    def reserve(self, timeout=5):
        """Atomically move a pending task into the processing list."""
        try:
            payload = self.client.blmove(
                self.queue_name,
                self.processing_queue_name,
                timeout,
                src="LEFT",
                dest="RIGHT",
            )
        except redis.exceptions.TimeoutError:
            return None

        if payload is None:
            return None

        return json.loads(payload)

    def acknowledge(self, task):
        """Remove a task from processing after durable handling."""
        payload = self._serialize(task)
        removed = self.client.lrem(
            self.processing_queue_name,
            1,
            payload,
        )
        return removed == 1

    def release(self, task):
        """Return an unhandled task to the pending queue atomically."""
        payload = self._serialize(task)

        script = """
        local removed = redis.call(
            'LREM', KEYS[1], 1, ARGV[1]
        )
        if removed == 1 then
            redis.call('LPUSH', KEYS[2], ARGV[1])
        end
        return removed
        """

        released = self.client.eval(
            script,
            2,
            self.processing_queue_name,
            self.queue_name,
            payload,
        )
        return released == 1

    def recover_processing(self):
        """
        Return tasks left in processing after a worker interruption.

        The Lua script preserves their original FIFO order and runs
        atomically so a concurrent reservation cannot split recovery.
        Call during worker startup before consuming new tasks.
        """
        script = """
        local recovered = 0
        while true do
            local payload = redis.call('RPOP', KEYS[1])
            if not payload then
                break
            end
            redis.call('LPUSH', KEYS[2], payload)
            recovered = recovered + 1
        end
        return recovered
        """

        return self.client.eval(
            script,
            2,
            self.processing_queue_name,
            self.queue_name,
        )

    def size(self):
        return self.client.llen(self.queue_name)


redis_queue = RedisInvestigationQueue()
