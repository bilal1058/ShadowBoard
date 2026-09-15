"""Asynchronous Worker Pool & Job Queue for Isolated Security Scans.

Provides queue management, worker concurrency limits, scan isolation,
and real-time job status tracking for enterprise operations.
"""

from typing import Dict, Any, Callable, Coroutine, Optional
import asyncio
import time
from pydantic import BaseModel, Field


class SecurityJob(BaseModel):
    job_id: str
    target_id: int
    scan_id: int
    status: str = "QUEUED"  # QUEUED | RUNNING | COMPLETED | FAILED | CANCELLED
    enqueued_at: float = Field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error_message: Optional[str] = None
    worker_id: Optional[str] = None


class WorkerPool:
    """Asynchronous worker pool running isolated security scans."""

    def __init__(self, max_concurrency: int = 4):
        self.max_concurrency = max_concurrency
        self.queue: asyncio.Queue = asyncio.Queue()
        self.jobs: Dict[str, SecurityJob] = {}
        self.active_workers: List[asyncio.Task] = []
        self._running = False

    async def start(self):
        """Starts background worker coroutines."""
        if self._running:
            return
        self._running = True
        for i in range(self.max_concurrency):
            task = asyncio.create_task(self._worker_loop(worker_id=f"worker-{i+1}"))
            self.active_workers.append(task)

    async def stop(self):
        """Gracefully stops all workers."""
        self._running = False
        for task in self.active_workers:
            task.cancel()
        self.active_workers.clear()

    async def enqueue_job(
        self,
        job_id: str,
        target_id: int,
        scan_id: int,
        task_fn: Callable[..., Coroutine],
        *args,
        **kwargs,
    ) -> SecurityJob:
        """Adds a security scan task to the isolated queue."""
        job = SecurityJob(job_id=job_id, target_id=target_id, scan_id=scan_id)
        self.jobs[job_id] = job
        await self.queue.put((job, task_fn, args, kwargs))
        return job

    def get_job(self, job_id: str) -> Optional[SecurityJob]:
        return self.jobs.get(job_id)

    async def _worker_loop(self, worker_id: str):
        while self._running:
            try:
                job, task_fn, args, kwargs = await self.queue.get()
                job.status = "RUNNING"
                job.started_at = time.time()
                job.worker_id = worker_id

                try:
                    await task_fn(*args, **kwargs)
                    job.status = "COMPLETED"
                except asyncio.CancelledError:
                    job.status = "CANCELLED"
                    break
                except Exception as e:
                    job.status = "FAILED"
                    job.error_message = str(e)
                finally:
                    job.completed_at = time.time()
                    self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.5)


# Global singleton worker pool
global_worker_pool = WorkerPool(max_concurrency=4)
