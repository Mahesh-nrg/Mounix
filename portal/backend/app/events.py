import asyncio
import uuid


class JobEventBus:
    """In-memory pub/sub for live job log streaming over WebSocket. Single-process app (one AVD
    means jobs already run strictly sequentially - see worker.py), so no Redis/broker needed."""

    def __init__(self) -> None:
        self._subscribers: dict[uuid.UUID, list[asyncio.Queue]] = {}

    def subscribe(self, job_id: uuid.UUID) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(job_id, []).append(queue)
        return queue

    def unsubscribe(self, job_id: uuid.UUID, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(job_id, [])
        if queue in subs:
            subs.remove(queue)
        if not subs:
            self._subscribers.pop(job_id, None)

    async def publish(self, job_id: uuid.UUID, event: dict) -> None:
        for queue in list(self._subscribers.get(job_id, [])):
            await queue.put(event)


bus = JobEventBus()
