#!/usr/bin/env python3

"""
RaceHunter - HTTP Race Client
Asyncio-based HTTP client with barrier synchronization for precise timing
© GHOSTSHINOBI 2025
"""

import asyncio
import time
import threading
from typing import List
from concurrent.futures import ThreadPoolExecutor
import httpx

from core import RaceConfig, RaceResponse, RaceStrategy, RaceAttempt


class RaceHTTPClient:
    """
    Production-grade HTTP client for race condition testing
    Supports multiple strategies with microsecond-level precision
    """

    def __init__(self, config: RaceConfig):
        self.config = config
        self.request_counter = 0

    async def execute_race(self) -> RaceAttempt:
        """
        Execute single race attempt with configured strategy
        Returns RaceAttempt with all responses
        """
        start_time = time.perf_counter()

        if self.config.strategy == RaceStrategy.ASYNC_BURST:
            responses = await self._async_burst_race()
        elif self.config.strategy == RaceStrategy.HTTP2_SINGLE_PACKET:
            responses = await self._http2_race()
        elif self.config.strategy == RaceStrategy.THREADING:
            responses = await self._threading_race()
        else:
            raise ValueError(f"Unknown strategy: {self.config.strategy}")

        total_time = time.perf_counter() - start_time

        attempt = RaceAttempt(
            attempt_number=0,  # to be set by engine
            requests_sent=len(responses),
            responses=responses,
            total_time=total_time
        )
        return attempt

    import httpx
    import asyncio
    import time
    from core import RaceResponse

    async def _async_burst_race(self) -> list[RaceResponse]:
        n = self.config.parallel_requests
        event = asyncio.Event()

        async def wait_and_request(req_id: int):
            await event.wait()
            start = time.perf_counter()
            try:
                async with httpx.AsyncClient(
                        http2=self.config.http2_enabled,
                        verify=self.config.verify_tls,
                        timeout=self.config.timeout,
                        follow_redirects=self.config.follow_redirects,
                        proxy=self.config.proxy) as client:

                    headers = {**self.config.headers}
                    if 'User-Agent' not in headers:
                        headers['User-Agent'] = self.config.user_agent

                    response = await client.request(
                        method=self.config.method,
                        url=self.config.target_url,
                        headers=headers,
                        content=self.config.body,
                        cookies=self.config.cookies
                    )
                    elapsed = time.perf_counter() - start

                    return RaceResponse(
                        request_id=req_id,
                        status_code=response.status_code,
                        body=response.text,
                        headers=dict(response.headers),
                        timing=elapsed,
                        error=None
                    )
            except httpx.ReadTimeout:
                return RaceResponse(
                    request_id=req_id,
                    status_code=0,
                    body="",
                    headers={},
                    timing=0.0,
                    error="ReadTimeout"
                )
            except Exception as e:
                return RaceResponse(
                    request_id=req_id,
                    status_code=0,
                    body="",
                    headers={},
                    timing=0.0,
                    error=str(e)
                )

        tasks = [asyncio.create_task(wait_and_request(i)) for i in range(n)]
        event.set()  # rilascia tutti
        responses = await asyncio.gather(*tasks)
        return list(responses)

    async def _http2_race(self) -> List[RaceResponse]:
        """
        Strategy 2: HTTP/2 Multiplexing
        Better precision ±5-15μs by sending requests in same TCP packet
        """
        n = self.config.parallel_requests
        async with httpx.AsyncClient(
                http2=True,
                verify=self.config.verify_tls,
                timeout=self.config.timeout,
                follow_redirects=self.config.follow_redirects,
                proxy=self.config.proxy,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1)
        ) as client:
            headers = {**self.config.headers}
            if 'User-Agent' not in headers:
                headers['User-Agent'] = self.config.user_agent

            async def send_request(req_id: int) -> RaceResponse:
                try:
                    start = time.perf_counter()
                    response = await client.request(
                        method=self.config.method,
                        url=self.config.target_url,
                        headers=headers,
                        content=self.config.body,
                        cookies=self.config.cookies
                    )
                    elapsed = time.perf_counter() - start

                    return RaceResponse(
                        request_id=req_id,
                        status_code=response.status_code,
                        body=response.text,
                        headers=dict(response.headers),
                        timing=elapsed,
                        error=None
                    )
                except Exception as e:
                    return RaceResponse(req_id, 0, "", {}, 0.0, str(e))

            tasks = [send_request(i) for i in range(n)]
            responses = await asyncio.gather(*tasks)
            return list(responses)

    async def _threading_race(self) -> List[RaceResponse]:
        """
        Strategy 3: Threading fallback
        Lower precision ±50-200μs but more compatible
        """

        n = self.config.parallel_requests
        barrier = threading.Barrier(n)
        responses = [None] * n

        def thread_request(req_id: int):
            try:
                barrier.wait()
                start = time.perf_counter()
                with httpx.Client(
                    http2=self.config.http2_enabled,
                    verify=self.config.verify_tls,
                    timeout=self.config.timeout,
                    follow_redirects=self.config.follow_redirects,
                    proxy=self.config.proxy
                ) as client:
                    headers = {**self.config.headers}
                    if 'User-Agent' not in headers:
                        headers['User-Agent'] = self.config.user_agent

                    response = client.request(
                        method=self.config.method,
                        url=self.config.target_url,
                        headers=headers,
                        content=self.config.body,
                        cookies=self.config.cookies
                    )
                    elapsed = time.perf_counter() - start

                    responses[req_id] = RaceResponse(
                        request_id=req_id,
                        status_code=response.status_code,
                        body=response.text,
                        headers=dict(response.headers),
                        timing=elapsed,
                        error=None
                    )
            except Exception as e:
                responses[req_id] = RaceResponse(
                    request_id=req_id,
                    status_code=0,
                    body="",
                    headers={},
                    timing=0.0,
                    error=str(e)
                )

        with ThreadPoolExecutor(max_workers=n) as executor:
            futures = [executor.submit(thread_request, i) for i in range(n)]
            for f in futures:
                f.result()

        return responses

    async def execute_baseline(self, num_requests: int = 5) -> RaceAttempt:
        """
        Execute baseline measurement (sequential requests)
        Used to establish normal behavior before race testing
        """
        responses = []
        start_time = time.perf_counter()

        async with httpx.AsyncClient(
                http2=self.config.http2_enabled,
                verify=self.config.verify_tls,
                timeout=self.config.timeout,
                follow_redirects=self.config.follow_redirects,
                proxy=self.config.proxy
        ) as client:
            headers = {**self.config.headers}
            if 'User-Agent' not in headers:
                headers['User-Agent'] = self.config.user_agent

            for i in range(num_requests):
                try:
                    req_start = time.perf_counter()
                    response = await client.request(
                        method=self.config.method,
                        url=self.config.target_url,
                        headers=headers,
                        content=self.config.body,
                        cookies=self.config.cookies
                    )
                    elapsed = time.perf_counter() - req_start

                    responses.append(RaceResponse(
                        request_id=i,
                        status_code=response.status_code,
                        body=response.text,
                        headers=dict(response.headers),
                        timing=elapsed,
                        error=None
                    ))
                except Exception as e:
                    responses.append(RaceResponse(
                        request_id=i,
                        status_code=0,
                        body="",
                        headers={},
                        timing=0.0,
                        error=str(e)
                    ))
                if i < num_requests - 1:
                    await asyncio.sleep(1.0)  # avoid rate limiting

        total_time = time.perf_counter() - start_time
        return RaceAttempt(
            attempt_number=0,
            requests_sent=len(responses),
            responses=responses,
            total_time=total_time
        )

    async def preflight_check(self) -> bool:
        """
        Send single test request to verify endpoint is reachable
        Returns True if endpoint responds (any status code)
        """
        try:
            async with httpx.AsyncClient(
                http2=self.config.http2_enabled,
                verify=self.config.verify_tls,
                timeout=self.config.timeout,
                proxy=self.config.proxy
            ) as client:
                headers = {**self.config.headers}
                if 'User-Agent' not in headers:
                    headers['User-Agent'] = self.config.user_agent

                response = await client.request(
                    method=self.config.method,
                    url=self.config.target_url,
                    headers=headers,
                    content=self.config.body,
                    cookies=self.config.cookies
                )
                return True
        except Exception as e:
            print(f"[!] Pre-flight check failed: {e}")
            return False
