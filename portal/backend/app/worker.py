"""Single background worker draining one queue. Jobs run strictly sequentially by design - there
is exactly one AVD, so true concurrency would just contend for the same device anyway."""

import asyncio
import logging
import uuid

from app.services.pipeline import run_job

logger = logging.getLogger(__name__)

_queue: asyncio.Queue[uuid.UUID] = asyncio.Queue()
_worker_task: asyncio.Task | None = None


async def _consume() -> None:
    while True:
        job_id = await _queue.get()
        try:
            await run_job(job_id)
        except Exception:
            # run_job already catches and records failures against the job itself; this is a
            # last-resort backstop so a failure *in that error handling* (e.g. the DB write inside
            # pipeline.py's own except-block failing) can never kill this loop. Without it, an
            # uncaught exception here would end `_worker_task` for good - every job enqueued after
            # would sit at QUEUED forever with the process otherwise looking perfectly healthy.
            logger.exception("Unhandled error processing job %s", job_id)
        finally:
            _queue.task_done()


def start() -> None:
    global _worker_task
    if _worker_task is None:
        _worker_task = asyncio.create_task(_consume())


async def enqueue(job_id: uuid.UUID) -> None:
    await _queue.put(job_id)
