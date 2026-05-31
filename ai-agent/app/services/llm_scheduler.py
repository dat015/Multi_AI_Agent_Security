from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from typing import Callable, Any
import logging


class LLMTaskScheduler:
    def __init__(
        self,
        api_keys: list[str],
        concurrency_per_key: int = 2,
        max_workers: int | None = None,
        logger: logging.Logger | None = None,
    ):
        self.api_keys = [k for k in api_keys if k]
        if not self.api_keys:
            raise ValueError("No API keys provided for LLM scheduler.")

        self.concurrency_per_key = max(1, int(concurrency_per_key))
        self.max_workers = max_workers
        self.logger = logger or logging.getLogger(__name__)
        self._semaphores = [Semaphore(self.concurrency_per_key) for _ in self.api_keys]

    def map(
        self,
        tasks: list[Callable[[str, int], Any]],
        fail_soft: bool = True,
    ) -> tuple[list[Any], list[Exception | None]]:
        results: list[Any] = [None] * len(tasks)
        errors: list[Exception | None] = [None] * len(tasks)

        if not tasks:
            return results, errors

        max_workers = self.max_workers or min(
            len(tasks),
            len(self.api_keys) * self.concurrency_per_key,
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for idx, task in enumerate(tasks):
                key_index = idx % len(self.api_keys)
                api_key = self.api_keys[key_index]
                futures.append(
                    executor.submit(self._run_task, idx, task, key_index, api_key)
                )

            for future in as_completed(futures):
                idx, result, err = future.result()
                if err is not None:
                    errors[idx] = err
                    if not fail_soft:
                        raise err
                else:
                    results[idx] = result

        return results, errors

    def _run_task(
        self,
        idx: int,
        task: Callable[[str, int], Any],
        key_index: int,
        api_key: str,
    ) -> tuple[int, Any, Exception | None]:
        sem = self._semaphores[key_index]
        sem.acquire()
        try:
            return idx, task(api_key, key_index), None
        except Exception as exc:
            self.logger.warning(
                "LLM task failed (index=%s, key_index=%s): %s",
                idx,
                key_index,
                exc,
            )
            return idx, None, exc
        finally:
            sem.release()
