from typing import Optional, AsyncGenerator, Literal, NotRequired, TypedDict, TYPE_CHECKING
from patch_func import _clear_frames
from dataclasses import dataclass, fields
import asyncio
import threading
import tempfile
import time
import weakref
import os
import random
import base64
import traceback
import sys
import logging

import curl_cffi

from selenium_driverless import webdriver
from selenium_driverless.types.target import Target
from selenium_driverless.types.context import Context
from websockets.exceptions import ConnectionClosedError

# All of this shit just to get a plain png out of the websites
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

from mitm_proxy import (
    DefaultPolicy,
    ResponseHeaders,
    RequestHeaders,
    Policy,
    SessionProxy,
    SocksProxyPool,
    SocksProxySession,
    ProxyConfig,
    SidecarManager,
    RequestInterceptor
    )

if TYPE_CHECKING:
    from .driverless import Init, ResponseCookie

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class DownloadWillBeginParams(TypedDict):
    frameId: str
    guid: str
    url: str
    suggestedFilename: str
    guid_file: NotRequired[str]
    named_file: NotRequired[str]

class DownloadProgressParams(TypedDict):
    guid: str
    totalBytes: int
    receivedBytes: int
    state: Literal['inProgress', 'completed']
    filePath: NotRequired[str]

class NoRedirectPolicy(DefaultPolicy):
    REDIRECTS = {301, 302, 303, 307, 308}

    def transform_response_headers(self, url: str, headers: ResponseHeaders) -> ResponseHeaders:
        headers = super().transform_response_headers(url, headers)

        for name, rule in self._response_rules.items():
            if rule.matcher.matches(url):
                if headers.status in self.REDIRECTS:
                    logger.debug("[Policy] Applying response rule %r for: %s", name, url)
                    headers.status = 299
                    headers.discard(b"location")
        return headers

    def transform_request_headers(self,
            url: str,
            headers: RequestHeaders,
        ) -> RequestHeaders:
        headers = super().transform_request_headers(url, headers)

        for name, rule in self._request_rules.items():
            if rule.matcher.matches(url):
                headers.insert_after(b"Sec-Fetch-Dest", b"Sec-Fetch-User", b"?1")
                logger.debug("[Policy] Applying request rule %r for: %s", name, url)

        return headers

class ProxyLoop:
    """Singleton *pool* of background event loops for SessionProxy instances.

    Previously this was a single loop on one thread carrying every
    session's MITM traffic, which capped the entire proxy at one core no
    matter how many sessions were active.  It now runs a small pool of
    loops (one daemon thread each) and hands each new session a loop via
    :meth:`next_loop`, spreading sessions across cores.

    On a free-threaded (no-GIL) build this scales close to linearly — the
    per-session SessionProxy state is loop-local and nothing is shared
    across loops (interceptor delivery already crosses threads via
    ``call_soon_threadsafe``, and the per-CONNECT sidecar sockets are
    opened on whichever loop is running).  Under the GIL it still helps,
    because the socket and TLS work that dominates the data path runs in C
    and releases the GIL, so loops on other threads make progress while one
    is inside a syscall.

    Pool size defaults to ``os.cpu_count()`` capped at 8.  Override with the
    ``PROXY_LOOP_WORKERS`` environment variable (1 reproduces the old
    single-loop behaviour exactly).
    """
    _instance: Optional[ProxyLoop] = None
    _lock = threading.Lock()

    @classmethod
    def get(cls) -> ProxyLoop:
        if cls._instance is not None and cls._instance.is_alive():
            logger.debug("ProxyLoop pool already created")
            return cls._instance

        with cls._lock:
            # Second check — another thread may have created it while
            # we were waiting for the lock
            if cls._instance is not None and cls._instance.is_alive():
                logger.debug("ProxyLoop pool already created by another thread")
                return cls._instance

            if cls._instance is not None:
                logger.warning("ProxyLoop pool was dead, recreating")
            else:
                logger.debug("ProxyLoop pool first-time creation")

            _instance = cls()
            cls._instance = _instance
            return _instance

    @staticmethod
    def _default_size() -> int:
        return max(1, min(8, os.cpu_count() or 1))

    def __init__(self, size: Optional[int] = None) -> None:
        self._size: int = size if size is not None else self._default_size()
        self._loops: list[asyncio.AbstractEventLoop] = []
        self._threads: list[threading.Thread] = []
        # Round-robin cursor for loop assignment.  Sessions are created
        # from a single thread (the control loop running initialize_mitm),
        # but guard it anyway so next_loop() is safe under free-threading.
        self._rr: int = 0
        self._rr_lock = threading.Lock()

        for i in range(self._size):
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=self._run, args=(loop,), daemon=True,
                name=f"SharedProxyLoop-{i}",
            )
            thread.start()
            self._loops.append(loop)
            self._threads.append(thread)

        logger.info(
            "ProxyLoop pool started (%d loop(s): %s)",
            self._size, [t.name for t in self._threads],
        )

    @staticmethod
    def _run(loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        logger.debug("ProxyLoop worker loop running")
        loop.run_forever()
        logger.debug("ProxyLoop worker loop stopped")

    def next_loop(self) -> asyncio.AbstractEventLoop:
        """Claim the next loop (round-robin) for a new session.

        The caller is expected to keep the returned loop for the whole
        lifetime of its session, so all of that session's
        ``run_coroutine_threadsafe`` calls land on the same loop.
        """
        with self._rr_lock:
            idx = self._rr
            self._rr = (self._rr + 1) % self._size
        return self._loops[idx]

    def is_alive(self) -> bool:
        alive = bool(self._loops) and all(
            t.is_alive() and not l.is_closed()
            for t, l in zip(self._threads, self._loops)
        )
        if not alive:
            logger.warning(
                "ProxyLoop pool not fully alive (threads=%s, closed=%s)",
                [t.is_alive() for t in self._threads],
                [l.is_closed() for l in self._loops],
            )
        return alive

    def stop(self) -> None:
        logger.info("ProxyLoop pool stopping (%d loop(s))...", len(self._loops))

        async def _cancel_all() -> None:
            loop = asyncio.get_running_loop()
            tasks = [t for t in asyncio.all_tasks(loop)
                     if t is not asyncio.current_task()]
            if not tasks:
                return
            for t in tasks:
                coro = t.get_coro()
                logger.debug(
                    "Cancelling task | name=%s | coro=%s | qualname=%s",
                    t.get_name(),
                    getattr(coro, "__name__", "<none>"),
                    getattr(coro, "__qualname__", "<none>"),
                )
                t.cancel()

            await asyncio.wait(tasks, timeout=10)
            still_alive = [t for t in tasks if not t.done()]
            if still_alive:
                logger.warning("%d task(s) refused to cancel: %s",
                            len(still_alive),
                            [t.get_name() for t in still_alive])

        # Drain each loop's tasks, then stop and join every worker thread.
        for loop in self._loops:
            try:
                fut = asyncio.run_coroutine_threadsafe(_cancel_all(), loop)
                fut.result(timeout=10)
            except TimeoutError:
                logger.warning("Cancelling tasks timed out on a worker loop")
            except Exception as e:
                logger.warning("Cancelling tasks on a worker loop, error: %s", e)

        for loop in self._loops:
            loop.call_soon_threadsafe(loop.stop)

        for thread in self._threads:
            thread.join(timeout=5)
            if thread.is_alive():
                logger.warning("ProxyLoop thread %s did not exit within 5s", thread.name)
            else:
                logger.debug("ProxyLoop thread %s joined", thread.name)

        for loop in self._loops:
            if not loop.is_closed():
                loop.close()
        logger.info("ProxyLoop pool stopped")

@dataclass(slots=True)
class Session:
    browser: DrivenBrowser
    fetcher: CffiFetcher
    stale_check: asyncio.Task[None]
    last_used: float
    in_use: int

    @property
    def weak_browser(self) -> weakref.ProxyType[DrivenBrowser]:
        return weakref.proxy(self.browser)

    @property
    def weak_fetcher(self) -> weakref.ProxyType[CffiFetcher]:
        return weakref.proxy(self.fetcher)

    async def close(self) -> None:
        async with asyncio.TaskGroup() as task_group:
            if self.browser:
                task_group.create_task(self.browser.terminate_session())
            if self.fetcher:
                task_group.create_task(self.fetcher.terminate_session())
        for f in fields(self):
            setattr(self, f.name, None)

class CffiFetcher:
    def __init__(self, session: str, config: Init, chromes_user_agent: str, socks_pool: SocksProxySession) -> None:
        self.session = session
        self.config = config
        self.chromes_user_agent = chromes_user_agent
        self.socks_pool = socks_pool
        self.cfii_session: Optional[curl_cffi.AsyncSession] = None

    async def get_browser(self) -> curl_cffi.AsyncSession:
        if self.cfii_session is not None:
            return self.cfii_session

        self.cfii_session = curl_cffi.AsyncSession(verify=self.config.verify_ssl)
        logger.debug(f"Curl cffi AsyncSession started {self.session}")
        return self.cfii_session

    def get_current_socks_proxy(self) -> Optional[str]:
        return self.socks_pool.get_proxy()

    async def terminate_session(self) -> None:
        if self.cfii_session:
            await self.cfii_session.close()
        del self.cfii_session

class DrivenBrowser:
    def __init__(self, controller: weakref.ReferenceType[BrowserController],
                config: Init,
                session: str,
                socks_pool: SocksProxySession,
                go_sidecar_proxy: Optional[weakref.ReferenceType[SidecarManager]]):
        self.controller = controller
        self.socks_pool = socks_pool
        self.session = session
        self.sessiontabs: dict[int, Target] = {}
        self.context: Optional[Context] = None
        self.current_id: int = random.randint(0, 100)
        self.downloads_dir: str = tempfile.mkdtemp(prefix=f"downloads_{session}_")
        logger.debug("Created dir %s", self.downloads_dir)

        self.config = config
        self.virt_disp: bool = config.virt_disp
        self.proxy_instance_port: int = 0
        self.go_sidecar_proxy = go_sidecar_proxy
        self.mitm_instance: SessionProxy
        self.mitm_proxy_loop: Optional[asyncio.AbstractEventLoop]

    async def start_browser(self) -> Context:
        controller = self.controller()
        if controller is None:
            raise Exception

        proxy: str = f"http://127.0.0.1:{self.proxy_instance_port}"
        context = await controller.get_context(proxy=proxy,download_dir=self.downloads_dir)
        if not context:
            raise Exception("NO CONTEXT!")

        logger.info("Started proxied context %s", proxy)
        return context

    async def initialize_mitm(self) -> None:
        self.mitm_instance = SessionProxy(
            host=self.config.host,
            port=0,  # OS-assigned
            socks_proxy=self.socks_pool,
            ca_cert=self.config.mitm_ca_cert,
            ca_key=self.config.mitm_ca_key,
            config=ProxyConfig(connect_timeout=60.0, verify_ssl=self.config.verify_ssl),
            sidecar=self.go_sidecar_proxy() if self.go_sidecar_proxy else None,
        )

        # Get the shared loop instead of creating a new thread
        proxy_loop = ProxyLoop.get()
        self.mitm_proxy_loop = proxy_loop.next_loop()

        # Start the proxy on the shared loop (cross-thread call)
        future = asyncio.run_coroutine_threadsafe(
            self.mitm_instance.start(),
            self.mitm_proxy_loop,
        )

        # Wait for port assignment (blocks the calling coroutine, not the loop)
        self.proxy_instance_port = await asyncio.wrap_future(future)

        logger.info(
            "SOCKS5 proxy started on port %d (shared loop)",
            self.proxy_instance_port,
        )

        self.set_intercept_policy(NoRedirectPolicy)

    async def get_browser(self) -> Context:
        if self.context is not None:
            return self.context

        logger.info("Starting new browser for %s", self.session)

        self.context = await self.start_browser()

        if not self.context:
            raise RuntimeError("No context")

        if self.virt_disp:
            await self.context.set_window_rect(x=0,y=0,width=1920,height=1080)

        logger.debug("Handed browser for %d", self.current_id)
        return self.context

    async def get_tab(self, requestid: int) -> tuple[Target, int]:
        if requestid in self.sessiontabs:
            return self.sessiontabs[requestid], self.current_id
        if self.current_id < 0:
            raise RuntimeError("Shutdown?")

        try:
            browser_context = await self.get_browser()
            tab: Target = await browser_context.new_window(type_hint="tab", url="about:blank")
            del browser_context
        except (ConnectionClosedError, TimeoutError):
            await self.broken_browser(self.current_id)
            return await self.get_tab(requestid)

        self.sessiontabs[requestid] = tab
        await tab.execute_cdp_cmd("Network.enable", {})
        await tab.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": True}, timeout=5)
        return tab, self.current_id

    async def get_cookies(self) -> list[ResponseCookie]:
        if not self.context:
            raise Exception("Context was collected")
        cookie_list: dict[str, list[ResponseCookie]] = await self.context.execute_cdp_cmd("Storage.getCookies", {"browserContextId": self.context._context_id})
        logger.debug(cookie_list)
        return cookie_list["cookies"]

    async def rotate_socks_proxy(self) -> bool:
        """
        Rotate the SOCKS5 proxy for this session.
        Returns True if successful, False otherwise.
        """
        try:
            new_proxy = self.socks_pool.rotate_proxy()
            if new_proxy:
                logger.info("Session %s rotated to SOCKS5 proxy: %s", self.session, new_proxy)
                await self.close_proxy_handlers()
                return True
            else:
                logger.warning("Failed to rotate SOCKS5 proxy for session %s", self.session)
                return False
        except Exception as e:
            logger.error("Error rotating SOCKS5 proxy: %s", str(e))
            return False

    async def set_socks_proxy(self, proxy_url: str) -> bool:
        try:
            new_proxy = self.socks_pool.set_proxy(proxy_url)
            if new_proxy:
                logger.info("Session %s rotated to SOCKS5 proxy: %s", self.session, new_proxy)
                await self.close_proxy_handlers()
                return True
            else:
                logger.warning("Failed to set SOCKS5 proxy for session %s", self.session)
                return False
        except Exception as e:
            logger.error("Error setting SOCKS5 proxy: %s", str(e))
            return False

    async def get_current_socks_proxy(self) -> Optional[str]:
        return self.socks_pool.get_proxy()

    @staticmethod
    async def listen_for_download(tab: Target, download_started: asyncio.Event) -> Optional[DownloadWillBeginParams]:
        '''Stolen from selenium_driverless.types.target.wait_download'''
        base_frame = await tab.base_frame
        _id = base_frame.get("id")
        _dir = [tab._context.downloads_dir][0]
        async for event in await tab.base_target.get_cdp_event_iter("Browser.downloadWillBegin"):
            base_frame = await tab.base_frame
            curr_id = base_frame.get("id")
            if event["frameId"] in [_id, curr_id]:
                download_started.set()
                if _dir:
                    guid_file = os.path.join(_dir, event["guid"])
                    named_file = os.path.join(_dir, "suggestedFilename")
                    event["guid_file"] = guid_file
                    event["named_file"] = named_file
                return event

    @staticmethod
    async def wait_for_download_completion(tab: Target, guid: str) -> AsyncGenerator[DownloadProgressParams, None]:
        async for event in await tab.base_target.get_cdp_event_iter("Browser.downloadProgress"):
            if event.get("guid") == guid:
                yield event

    def set_intercept_policy(self, policy: type[Policy]) -> None:
        self.mitm_instance.set_policy(policy(self.mitm_instance))

    async def destroy_tab(self, requestid: int, used: int = 0) -> None:
        tab = self.sessiontabs.pop(requestid, None)
        if not self.context:
            logger.warning("No context, shutdown?")
            return
        if tab:
            target_id = tab.id

            try:
                await tab.execute_cdp_cmd("Page.close", {}, timeout=5)
            except Exception as e:
                logger.debug(e)
                try:
                    await tab.execute_cdp_cmd("Target.closeTarget", {"targetId": target_id}, timeout=5)
                except Exception as e:
                    logger.warning(e)
                try:
                    await self.context.execute_cdp_cmd("Target.closeTarget", {"targetId": target_id}, timeout=5)
                except Exception as e:
                    logger.warning(e)
                try:
                    await tab.base_target.execute_cdp_cmd("Target.closeTarget", {"targetId": target_id}, timeout=5)
                except Exception as e:
                    logger.warning(e)
        else:
            logger.debug("Requestid not found. Chrome was destroyed?")

        if len(await self.context.window_handles) > int(used*2):
            await self.broken_browser(self.current_id)

    async def mitm_shutdown(self) -> None:
        """Stop the proxy server"""
        await self.close_proxy_handlers()
        if not hasattr(self, "mitm_instance") or not self.mitm_instance:
            return
        loop = self.mitm_proxy_loop
        if loop is None or loop.is_closed():
            return

        logger.info("Stopping MITM proxy...")

        # Stop the server
        future = asyncio.run_coroutine_threadsafe(
            self.mitm_instance.stop(), loop
        )
        try:
            await asyncio.wait_for(asyncio.wrap_future(future), timeout=10.0)
        except asyncio.TimeoutError as e:
            logger.warning("MITM stop() timed out; cancelling")
            future.cancel()
        except Exception as e:
            logger.warning("stop error: %s", e)

        logger.info("MITM proxy stopped")

    async def broken_browser(self, current_id: int) -> None:
        traceback.print_stack()
        if current_id != self.current_id:
            logger.debug('Not matched')
            return
        cookies: Optional[list[dict[str, str]]] = None
        try:
            cookies = await (await self.get_browser()).get_cookies()
            logger.debug(cookies)
        except Exception:
            logger.warning('Dead browser')

        await self.destroy_driver(self.current_id)
        await self.close_proxy_handlers()

        if cookies:
            for cookie in cookies:
                logger.debug(cookie)
                await (await self.get_browser()).add_cookie(cookie)

    async def destroy_driver(self, current_id: int) -> None:
        if current_id != self.current_id:
            logger.debug('Not matched')
            return
        if self.current_id > 0:
            self.current_id = random.randint(0, 1000)
        if not self.context:
            return 

        try:
            await self.clear_downloads(delete_folder=True)
        except Exception as e:
            logger.warning("Unable to clear downloads.", exc_info=e)

        try:
            context_id = self.context.context_id
            await self.context.execute_cdp_cmd("Target.disposeBrowserContext",
                                                        {"browserContextId": context_id})
            # await context.quit() # ? Raises CDP exception Not Allowed
        except Exception as e:
            logger.warning("Quit context returned an error: %s", str(e))

        logger.debug("Stopped: %s", str(self.context))
        self.context = None
        self.sessiontabs.clear()

    async def clear_downloads(self, delete_folder: bool = False) -> None:
        if os.path.exists(self.downloads_dir) and os.path.isdir(self.downloads_dir):
            for root, dirs, files in os.walk(self.downloads_dir, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            logger.debug("Directory '%s' has been cleared.", self.downloads_dir)
            if delete_folder:
                os.rmdir(self.downloads_dir)
                logger.debug("Directory '%s' has been removed.", self.downloads_dir)
        else:
            logger.debug("Directory '%s' does not exist or is not a directory.", self.downloads_dir)

    async def close_proxy_handlers(self, timeout: float = 10.0) -> None:
        """Close all proxy handlers from a foreign async context."""
        loop = self.mitm_proxy_loop
        if loop is None or loop.is_closed():
            return
        future = asyncio.run_coroutine_threadsafe(
            self.mitm_instance.close_all_handlers(), loop
        )
        # Block in an executor so we don't stall our own event loop
        await asyncio.get_running_loop().run_in_executor(
            None, future.result, timeout
        )

    async def terminate_session(self) -> None:
        self.current_id = -1
        await self.destroy_driver(-1)
        del self.context
        await self.mitm_shutdown()
        del self.config
        logger.info("Terminated session: %s", self.session)
        return None

class BrowserController:
    def __init__(self, config: Init) -> None:
        self.config = config
        self.main_driver: webdriver.Chrome

    @staticmethod
    def get_certificate_spki_hash(cert_path: str) -> str:
        with open(cert_path, 'rb') as f:
            cert_data: bytes = f.read()
        cert = load_pem_x509_certificate(cert_data, default_backend())

        public_key = cert.public_key()
        public_key_der: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(public_key_der)
        hash_bytes: bytes = digest.finalize()

        base64_hash: str = base64.b64encode(hash_bytes).decode('utf-8')

        return base64_hash

    async def initialize_main_driver(self) -> None:
        _options: webdriver.ChromeOptions = webdriver.ChromeOptions()
        if self.config.chromium:
            _options.binary_location = self.config.chromium
        _options.add_argument("--no-sandbox")
        _options.add_argument("--disable-setuid-sandbox")
        # _options.add_argument("--no-service-autorun")
        # _options.add_argument("--no-first-run")
        # _options.add_argument("--password-store=basic")
        _options.add_argument("--disable-client-hints")
        _options.add_argument("--disable-notifications")
        _options.add_argument("--disable-infobars")
        _options.add_argument("--disable-blink-features=AutomationControlled")
        _options.add_argument("--disable-features=DisableLoadExtensionCommandLineSwitch")
        _options.add_argument("--enable-features=RemoveClientHints,ReduceUserAgentDataLinuxPlatformVersion")
        _options.add_argument("--disk-cache-size=1")
        _options.add_argument("--media-cache-size=1")
        _options.add_argument("--disk-cache-dir=/dev/null")

        _options.update_pref("download.prompt_for_download", False)
        # _options.add_argument("--net-log-capture-mode=Everything")
        # _options.add_argument("--log-net-log=/tmp/chrome.json")
        # _options.add_argument("--enable-logging")
        # _options.add_argument("--v=1")
        # _options.add_argument("--auto-open-devtools-for-tabs")

        # _options.add_argument("--disable-web-security")
        # These launch options '--allow-running-insecure-content', '--allow-mixed-content' are set bc to allow downloading some images. Test url https://archiveofourown.org/works/500595
        # _options.add_argument("--allow-running-insecure-content")
        # _options.add_argument("--allow-mixed-content")

        _options.add_argument(f'--ignore-certificate-errors-spki-list={BrowserController.get_certificate_spki_hash(self.config.mitm_ca_cert)}')

        if self.config.adblock:
            logger.debug(self.config.adblock)
            _options.add_extension(self.config.adblock)
        if self.config.extension:
            _options.add_extension(self.config.extension)
        self.main_driver = await webdriver.Chrome(max_ws_size=2 ** 30, options=_options)
        t = await self.main_driver.current_target_info
        self.targetId_main_driver = t.id
        info = await self.main_driver.execute_cdp_cmd("Browser.getVersion")
        self.user_agent = info["userAgent"]

        await self.main_driver.set_window_rect(x=0, y=0, width=50, height=50)
        del _options

    async def destroy_main_driver(self) -> None:
        try:
            await self.main_driver.quit()
            logger.debug("Stopped: %s", str(self.main_driver))
        except Exception as e:
            logger.warning("Driver quit returned an error: [%s]", str(e))

    async def check_main_driver(self) -> None:
        try:
            _ = await self.main_driver.execute_cdp_cmd('Target.getTargetInfo', {"targetId": self.targetId_main_driver})
        except Exception as e:
            logger.debug(e)
            await self.destroy_main_driver()
            await self.initialize_main_driver()

    async def get_context(self, proxy: str, download_dir: str) -> Optional[Context]:
        try:
            context = await self.main_driver.new_context(proxy_server=proxy)
            # Image testing selenium proxy https://archiveofourown.org/works/61648471?view_full_work=true&view_adult=true
            await context.set_download_behaviour('allowAndName', download_dir)
        except Exception as e:
            logger.warning("Error in creating context %s", str(e))
            await self.check_main_driver()
            return None
        return context

class SessionManager:
    def __init__(self, config: Init) -> None:
        self.sessions: dict[str, Session] = {}
        self.config = config
        self.main_browser: BrowserController
        self.go_sidecar_proxy: Optional[SidecarManager] = None

        self.browser_lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    async def initialize(cls, config: Init) -> SessionManager:
        instance = cls(config)
        await instance.initialize_proxy()
        main_browser = BrowserController(config)
        await main_browser.initialize_main_driver()
        instance.main_browser = main_browser
        return instance

    async def initialize_proxy(self) -> None:
        try:
            if self.config.impersonate_chrome:
                sidecar = SidecarManager(
                    binary_path=self.config.impersonate_chrome,
                    auto_restart=False,
                    verify_ssl=self.config.verify_ssl
                )
                await sidecar.start()
                self.go_sidecar_proxy = sidecar
                logger.info(sidecar)
        except Exception as e:
            logger.warning(e)

    async def get_session(self, session: str) -> Session:
        if session in self.sessions:
            logger.debug("Returning session %s", session)
            if self.sessions[session].browser.current_id < 0:
                await self.remove_session(session)
                raise RuntimeError("Browser is shutting down.")
            return self.sessions[session]

        logger.debug("New session %s", session)

        socks_pool = SocksProxySession(socks_pool=SocksProxyPool(self.config.socks5_file), session=session)

        drivenbrowser: DrivenBrowser = DrivenBrowser(controller=weakref.ref(self.main_browser),
                                                    config=self.config,
                                                    session=session,
                                                    socks_pool=socks_pool,
                                                    go_sidecar_proxy=weakref.ref(self.go_sidecar_proxy) if self.go_sidecar_proxy else None)
        await drivenbrowser.initialize_mitm()
        weakref.finalize(drivenbrowser, lambda: logger.debug("Garbage collected driver"))

        cffi = CffiFetcher(session=session,
                        config=self.config,
                        socks_pool=socks_pool,
                        chromes_user_agent=self.main_browser.user_agent)
        _ = await cffi.get_browser()

        task: asyncio.Task[None] = asyncio.create_task(self.browser_auto_destruction(self.config.driver_timeout, session))

        self.sessions[session] = Session(browser=drivenbrowser,fetcher=cffi,stale_check=task, last_used=time.time(), in_use=0)

        del drivenbrowser, cffi, task
        return self.sessions[session]

    async def browser_auto_destruction(self, timeout: int, session: str) -> None:
        await asyncio.sleep(0.1)
        sess = self.sessions.get(session)
        if not sess:
            logger.warning("Session not registered")
            return
        try:
            while True:
                logger.debug(f"Checking {sess.in_use}")

                idle = time.time() - sess.last_used
                if not sess.in_use and idle >= timeout:
                    break

                await asyncio.sleep(max(timeout - idle, 2.0))
        except TypeError as e:
            logger.debug(f"Browser got yeeted {e}")
        logger.debug(f"Yeeting the browser")
        await self.remove_session(session)

    async def remove_session(self, session: str) -> None:
        sess = self.sessions.pop(session, None)
        logger.debug(f"remove_session {sess}")
        if sess is None:
            return

        stale_check = sess.stale_check
        if stale_check is not asyncio.current_task():
            stale_check.cancel()
            try:
                await stale_check
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug("stale_check returned an exception %s: %s", session, e)

        browser = sess.browser
        try:
            await asyncio.wait_for(sess.close(), timeout=30.0)
        except Exception as e:
            logger.error("terminate_session timed out for %s with: %s", session, traceback.format_exc())

        # I gave up, AI generated frame cleanup
        if sys.getrefcount(browser) > 2:
            for t in asyncio.all_tasks():
                if not t.done():
                    logger.debug("pending task %r: %s", t.get_name(), t.get_stack(limit=8))
            cleared = await _clear_frames(browser, module_filter="driverless.py")
            logger.debug(cleared)

        logger.debug("Destroyed %s", session)

        return None

    async def shutdown_sessions(self) -> None:
        tasks: list[asyncio.Task[None]] = [asyncio.create_task(self._shutdown_session(key))
             for key in list(self.sessions.keys())]
        await asyncio.gather(*tasks)

        if self.go_sidecar_proxy:
            await self.go_sidecar_proxy.stop()
        await self.main_browser.destroy_main_driver()

    async def _shutdown_session(self, session: str) -> None:
        logger.debug("Force %s", session)
        try:
            self.sessions[session].stale_check.cancel()
            logger.debug("Stopped driver for: %s", session)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("Unable to shutdown", exc_info=e)
