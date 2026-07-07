from __future__ import annotations
import patch_func

from typing import Optional, Literal, Any, TypedDict, TextIO, cast, Callable, NotRequired
import asyncio, zlib, argparse, configparser, sys, signal, logging
import ssl, base64, hashlib, json, re
import weakref
from xvfbwrapper import Xvfb
from asyncio.sslproto import SSLProtocol
from asyncio import StreamReader, StreamWriter, StreamReaderProtocol

from selenium_driverless.types.by import By
from selenium_driverless.types.target import Target
from selenium_driverless.types.webelement import NoSuchElementException, WebElement
from cdp_socket.exceptions import CDPError
from websockets.exceptions import ConnectionClosedError

from mitm_proxy import (
    ProxyError,
    ColoredFormatter,
    set_sidecar_log_level,
    set_proxy_log_level)

from fetcher import (DownloadWillBeginParams,
    SessionManager,
    Session,
    DrivenBrowser,
    CffiFetcher,
    ProxyLoop)

from curl_cffi import AsyncSession, ProxySpec
from http.cookiejar import CookieJar, Cookie

# used for the timestamp in session
import time

# used for encoding POST parameters and extracting base website from urls
import urllib.parse

# used for choosing the random proxy ip, choosing the display
import random

# only used for debugging
import traceback

# Making and checking download dir, setting vars in the env for xvfb
import os

#import pdb
#        pdb.set_trace()
# gc.set_debug(gc.DEBUG_SAVEALL)

class ServerResponse(TypedDict):
    code: int
    content_type: str
    cookies: str
    source: str
    errors: str

class ServerRequest(TypedDict):
    method: Literal["GET", "POST"]
    url: str
    headers: dict[str,str]
    parameters: str
    image: Literal["True", "False"]
    cookies: list[RequestCookie]
    session: str
    heartbeat: str

class RequestCookie(TypedDict):
    name: str
    value: str
    domain: str
    path: str
    expires: int
    secure: bool
    httpOnly: bool

class CookiePartitionKey(TypedDict):
    topLevelSite: str
    hasCrossSiteAncestor: bool

class ResponseCookie(TypedDict):
    name: str
    value: str
    domain: str
    path: str
    expires: int
    size: int
    httpOnly: bool
    secure: bool
    session: bool
    # Optional
    sameSite: NotRequired[str]
    partitionKey: NotRequired[CookiePartitionKey]
    partitionKeyOpaque: NotRequired[bool]
    # Chrome only
    priority: NotRequired[str]
    sourceScheme: NotRequired[str]
    sourcePort: NotRequired[int]
    sameParty: NotRequired[bool]

class ChromeRequestInfo(TypedDict):
    url: str
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    headers: dict[str, str]
    initialPriority: Literal["VeryLow", "Low", "Medium", "High", "VeryHigh"]
    referrerPolicy: Literal["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"]

class ChromeRequest(TypedDict):
    requestId: str
    request: ChromeRequestInfo
    frameId: str
    resourceType: str

class ChromeResponseHeaders(TypedDict):
    name: str
    value: str

class ChromeResponse(ChromeRequest, total=False):
    responseStatusCode: int
    responseStatusText: str
    responseHeaders: list[ChromeResponseHeaders]
    responseErrorReason: str

class ChromeContinueRequest(TypedDict, total=False):
    requestId: str
    headers: list[ChromeResponseHeaders]
    interceptResponse: bool
    responsePhrase: str

class MessageFormatingError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)

class ImageError(Exception):
    def __init__(self, message: str, res: tuple[int, str, bytes, str]) -> None:
        super().__init__(str(message))
        self.response = res

class RefererError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)

class LogSSLProtocol(SSLProtocol):
    def _on_handshake_complete(self, handshake_exc: Optional[BaseException]) -> None:
        if handshake_exc is not None:
            logger.debug("TLS handshake failed", exc_info=handshake_exc)
        super()._on_handshake_complete(handshake_exc)

class Stats:
    def __init__(self) -> None:
        self.failed_fetches: dict[str, str] = {}
        self.requests_used: dict[str, str] = {}

    def add_failed(self, url: str, reason: str) -> None:
        self.failed_fetches[url] = reason

    def print_statistics(self) -> None:
        # if self.requests_used:
        #     logger.warning("Fallbacks on requests:")
        #     for url, reason in self.requests_used.items():
        #         logger.warning("%s : %s", url, reason)
        if self.failed_fetches:
            logger.warning("Failed Fetches:")
            for url, reason in self.failed_fetches.items():
                logger.warning("%s : %s", url, reason)

class Init:
    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop
        self.statistics: Stats
        self.proxy_instance: ProxyServer

        self.in_progress: bool = False
        self.config: configparser.ConfigParser = configparser.ConfigParser()
        if os.path.exists(args.config):
            self.config.read(args.config)

        self.log_lvl = logging.INFO
        if args.debug:
            self.log_lvl = logging.DEBUG
        if args.trace:
            self.log_lvl = 5
        logger.setLevel(self.log_lvl)
        ch.setLevel(self.log_lvl)
        set_proxy_log_level(self.log_lvl)
        set_sidecar_log_level(self.log_lvl)

    def config_ini(self) -> None: # ConfigDict:
        self.port: int = (
            args.port
            if args.port is not None
            else self.config.getint("server", "port", fallback=23000)
        )
        self.host: str = (
            args.host
            if args.host is not None
            else self.config.get("server", "host", fallback='127.0.0.1')
        )
        self.chromium: Optional[str] = (
            args.chrome
            if args.chrome is not None
            else self.config.get("server", "chrome", fallback=None)
        )
        self.driver_timeout: int = (
            args.driver_timeout
            if args.driver_timeout is not None
            else self.config.getint("server", "driver_timeout", fallback=60)
        )
        self.virt_disp: bool = (
            args.xvfb
            if args.xvfb is not None
            else self.config.getboolean("server", "xvfb", fallback=True)
        )
        if self.virt_disp:
            self.disp: Xvfb = Xvfb(width=1920,height=1080)
            self.disp.start()
            #from cdp_patches.input import AsyncInput
            #self.AsyncInput: AsyncInput = AsyncInput
            logger.info("Using xvfb :%s", str(self.disp.new_display))
            # Now chrome will not launch in the xvfb without this
            os.environ["XDG_SESSION_TYPE"] = "x11"

        self.cert: str = (
            args.cert
            if args.cert is not None
            else self.config.get("server", "cert")
        )
        self.key: str = (
            args.key
            if args.key is not None
            else self.config.get("server", "key")
        )
        self.client_cert: str = (
            args.cacert
            if args.cacert is not None
            else self.config.get("server", "cacert")
        )
        logger.debug((self.client_cert, self.key, self.cert))

        self.adblock: Optional[str] = (
            args.ublock
            if args.ublock is not None
            else self.config.get("server", "ublock", fallback=None)
        )
        self.extension: Optional[str] = self.config.get("server", "extension", fallback=None)

        self.socks5_file: str = (
            args.socks5_file
            if hasattr(args, 'socks5_file') and args.socks5_file is not None
            else self.config.get("server", "socks5_file", fallback='')
        )
        self.verify_ssl: bool = (
            args.verify_ssl
            if hasattr(args, 'verify_ssl')
            else self.config.getboolean("server", "verify_ssl", fallback=True)
        )
        if not self.verify_ssl:
            logger.warning("SSL cert verification disabled")
        # For TLS interception, use dedicated CA cert/key
        # Generate these with: python3 generate_ca.py --output-dir ./certs
        self.mitm_ca_cert: str = (
            args.mitm_ca_cert
            if hasattr(args, 'mitm_ca_cert') and args.mitm_ca_cert is not None
            else self.config.get("server", "mitm_ca_cert", fallback=self.cert)
        )
        self.mitm_ca_key: str = (
            args.mitm_ca_key
            if hasattr(args, 'mitm_ca_key') and args.mitm_ca_key is not None
            else self.config.get("server", "mitm_ca_key", fallback=self.key)
        )
        self.impersonate_chrome: str = (
            args.impersonate_chrome
            if hasattr(args, 'impersonate_chrome') and args.impersonate_chrome
            else self.config.get("server", "impersonate", fallback='')
        )

    def prepserver(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.loop.set_debug(False)
        asyncio.set_event_loop(self.loop)

        self.statistics = Stats()
        self.config_ini()

        def task_exception_handler(task: asyncio.Task[None]) -> None:
            try:
                task.result()
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.error("Exception in task: %s", traceback.format_exc())
                if not self.in_progress:
                    self.terminated()

        try:
            self.proxy_instance = ProxyServer(self)
            self.loop.add_signal_handler(signal.SIGTERM, self.terminated)
            self.loop.add_signal_handler(signal.SIGINT, self.terminated)
            run_server_task: asyncio.Task[None] = self.loop.create_task(self.proxy_instance.run_server(self.loop))
            run_server_task.set_name("Server")
            run_server_task.add_done_callback(task_exception_handler)
            self.loop.run_forever()
        except Exception as e:
            logger.critical('Exception %s', e)
            self.terminated()

        self.statistics.print_statistics()

    async def graceful_shutdown(self) -> None:
        try:
            await self.proxy_instance.shutdown()
            logger.debug("Proxy shutdown")
        except Exception:
            logger.error(traceback.format_exc())

        tasks_to_await: list[asyncio.Task[None]] = [
            t
            for t in asyncio.all_tasks(self.loop)
            if t.get_name() == "remove_session"
        ]

        logger.debug(f"Awaiting tasks {tasks_to_await}")
        results = await asyncio.gather(*tasks_to_await, return_exceptions=True)
        logger.debug(results)

        try:
            await asyncio.to_thread(ProxyLoop.get().stop)
        except Exception as e:
            logger.warning("Failed to stop shared proxy loop: %s", e)

        logger.debug("Cancelling remaining tasks.")
        tasks_to_cancel: list[asyncio.Task[None]] = [
            t
            for t in asyncio.all_tasks(self.loop)
            if t.get_name() == "BrowserWorker" or t.get_name() == "Server" or t.get_name() == "ServerTask"
        ]

        for task in tasks_to_cancel:
            logger.debug("Cancelled: %s", task)
            task.cancel()

        try:
            if self.virt_disp:
                self.disp.stop()
                logger.debug("Stopped Display")
        except Exception:
            pass

        await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
        logger.debug("Tasks cancelled.")

        tasks_to_kill: list[asyncio.Task[None]] = [task for task in asyncio.all_tasks(self.loop) if task.get_name() != 'Shutdown']
        for t in tasks_to_kill:
            #print("coro:", t.get_coro())
            #print("stack:", t.get_stack(limit=5))
            #print("created at:", getattr(t, "_source_traceback", None))
            t.cancel()
            try:
                await t
            except Exception as e:
                logger.debug(e)
            except asyncio.CancelledError:
                logger.debug("Task Cancelled")
        try:
            async with asyncio.timeout(10):
                logger.debug(tasks_to_kill)
                await asyncio.gather(*tasks_to_kill)
        except asyncio.TimeoutError:
            logger.warning("Timeout!")
            for task in tasks_to_kill:
                if not task.done():
                    logger.error("Task %s is not done.", task.get_name())
                if task.exception():
                    logger.error("Task %s raised an exception: %s", task.get_name(), task.exception())

    def terminated(self) -> None:
        logger.debug("Terminated")
        if self.in_progress:
            logger.info('Received CNTR+C, exiting...')
            sys.exit(1)

        self.in_progress = True
        shutdown_task: asyncio.Task[None] = self.loop.create_task(self.graceful_shutdown())
        shutdown_task.set_name("Shutdown")
        logger.info('Shutdown task created.')

        def stop_loop_callback(future: asyncio.Task[None]) -> None:
            logger.info("Shutdown complete.")
            try:
                future.result()
            except asyncio.CancelledError:
                logger.debug("Cancelled")
            except Exception as e:
                logger.error("On exit: %s", str(e))
            self.loop.stop()

        shutdown_task.add_done_callback(stop_loop_callback)

class ProxyServer:
    def __init__(self, init: Init) -> None:
        self.server: asyncio.base_events.Server
        self.session_manager: SessionManager
        self.server_task: asyncio.Task[None]

        self.init: Init = init
        self.stats: Stats = self.init.statistics
        self.connections: dict[bytes,asyncio.Task[None]] = {}

    async def run_server(self, loop: asyncio.AbstractEventLoop) -> None:
        try:
            self.session_manager = await SessionManager.initialize(self.init)

            context: ssl.SSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(
                certfile=self.init.cert,
                keyfile=self.init.key,
            )
            context.load_verify_locations(cafile=self.init.client_cert)

            def connection(reader: StreamReader, writer: StreamWriter) -> None:
                client_id = os.urandom(32)
                client = loop.create_task(self.handle_client(reader, writer), name=f"ClientConn{client_id}")
                self.connections[client_id] = client

                def handle_result(task: asyncio.Task[None]) -> None:
                    del self.connections[client_id]
                    try:
                        result = task.result()
                        logger.debug("Client %s", result)
                    except asyncio.CancelledError:
                        logger.debug("Cancelled")
                    except Exception as e:
                        logger.error("Error handling client: %s", str(e))

                client.add_done_callback(handle_result)

            def protocol_factory() -> LogSSLProtocol:
                # For each new connection, build a StreamReader + protocol
                reader: StreamReader = StreamReader()
                sr_protocol: StreamReaderProtocol = StreamReaderProtocol(
                    reader,
                    client_connected_cb = connection)

                waiter: asyncio.Future[None] = loop.create_future()
                proto = LogSSLProtocol(loop, sr_protocol, context, waiter=waiter, server_side=True)

                # log handshake result
                def log_handshake_result(future: asyncio.Future[None]) -> None:
                    try:
                        future.result()
                    except Exception as e:
                        logger.error("Handshake failed: %s", e, exc_info=True)

                waiter.add_done_callback(log_handshake_result)
                return proto

            self.server = await loop.create_server(
                protocol_factory=protocol_factory,
                host=self.init.host,
                port=self.init.port,
            )
        except Exception:
            logger.critical("Error in creating as server: %s", traceback.format_exc())
            self.init.terminated()
            return

        logger.info("Serving FFF proxy on %s, %d", self.server.sockets[0].getsockname(), os.getpid())

        asyncio.set_event_loop(loop)
        self.server_task = asyncio.create_task(self.server.serve_forever(), name="ServerTask")
        await self.server_task

    async def handle_client(self, reader: StreamReader, writer: StreamWriter) -> None:
        content: ServerResponse = {"code": -1, "content_type": "None", "source": "RmFpbGVk", "cookies": "None", "errors": "Failed to process a client."}
        client: Optional[ClientRequest] = None
        client_task: Optional[asyncio.Task[ServerResponse]] = None
        heartbeat: Optional[asyncio.Task[None]] = None

        packet: bytes = await self.receive_request(reader)
        request: ServerRequest = await self.decrypt(packet)

        async with asyncio.timeout(60):
            try:
                client_session = await self.session_manager.get_session(request["session"])
            except Exception as e:
                logger.error(traceback.format_exc())
                logger.error("Failed to get browser")
                await self.send_response(writer, await self.encrypt(response=content))
                raise e

        try:
            heartbeat = asyncio.create_task(self.heartbeat(writer, request["heartbeat"]))
            try:
                client = ClientRequest(self.stats, client_session)
                weakref.finalize(client, lambda: logger.debug("Garbage collected client"))
                client_task = asyncio.create_task(client.main(request))
                client_session.in_use += 1
                content = await client_task
            except asyncio.CancelledError as e:
                logger.debug(e)
                self.stats.add_failed(request["url"], "CancelledError")
            except Exception as e:
                msg = traceback.format_exc()
                logger.warning(msg)
                self.stats.add_failed(request["url"], str(msg))
                content['errors'] = msg
            finally:
                client_session.last_used = time.time()
                client_session.in_use -= 1
                if client:
                    if sys.getrefcount(client) > 2:
                        logger.warning("Client will not be cleared!")

                    del client
                    logger.debug("Deleted the client %s", request["session"])

            if content["code"] == -1:
                logger.warning("Failed to fetch %s", request["url"])
                self.stats.add_failed(request["url"], content["errors"])
        except ssl.SSLError as e:
            self.stats.add_failed(request["url"], str(e))
            logger.error("SSL error: %s", str(e))
        except MessageFormatingError as e:
            self.stats.add_failed(request["url"], str(e))
            logger.error(e)
        except ConnectionResetError as e:
            logger.warning(e)
        except Exception as e:
            self.stats.add_failed(request["url"], str(e))
            logger.error("Unexpected error in handle_client: %s", traceback.format_exc())
            raise e
        finally:
            logger.debug("Finalizing client")
            response = await self.encrypt(response=content)
            async with asyncio.TaskGroup() as tg:
                if heartbeat:
                    tg.create_task(self._cancel_task(heartbeat))
                if client_task:
                    tg.create_task(self._cancel_task(client_task))
                tg.create_task(self.send_response(writer, response))
            await self.writer_close_task(writer)

    async def heartbeat(self, writer: StreamWriter, beat: str) -> None:
        while True:
            logger.debug("Heartbeat: %s", beat)
            await asyncio.sleep(float(beat))
            logger.debug("Heartbeat %s", str(writer))
            x: bytes = bytes('KeepAlive', 'utf-8')
            content: ServerResponse = {"code": -400, "content_type": "KeepAlive", "cookies": "None", "source": base64.b64encode(x).decode(), "errors": "None"}
            packet = await self.encrypt(content)
            await self.send_response(writer, packet)

    async def receive_request(self, reader: StreamReader) -> bytes:
        parts = bytearray()
        while True:
            data = await reader.read(8192)
            if not data:
                logger.debug("No data received, closing connection.")
                raise ConnectionResetError("No Data")
            parts.extend(data)
            if b"\0" in data:
                logger.debug('End of data received')
                break
        return bytes(parts)

    async def send_response(self, writer: StreamWriter, response: bytes) -> None:
        writer.write(response)
        await writer.drain()
        logger.debug("Sent %s bytes successfully.", len(response))

    async def decrypt(self, packet: bytes) -> ServerRequest:
        logger.debug("Decode received data")

        b64_checksum: bytes = packet[:44]
        b64_packet: bytes = packet[44:-1]
        checksum: bytes = base64.b64decode(b64_checksum)
        decrypted_packet: bytes = base64.b64decode(b64_packet)

        # expected_hmac = hmac.new(self.init.secret, decrypted_packet, hashlib.sha256).digest()
        if not checksum == hashlib.sha256(decrypted_packet).digest():
            logger.debug(packet)
            logger.debug(decrypted_packet)
            logger.error("Recv: %s", str(checksum))
            logger.error("Calc: %s", str(hashlib.sha256(decrypted_packet).digest()))
            raise ValueError("Validation error!")

        try:
            packet_l: list[str] = decrypted_packet.decode("utf-8").split("\x01\x7f\x01", 7)

            if packet_l[0] not in ['GET', 'POST']:
                raise ValueError(f"Invalid method: {packet_l[0]}")
            method: Literal['GET', 'POST'] = cast(Literal['GET', 'POST'], packet_l[0])

            if packet_l[4] not in ['True', 'False']:
                raise ValueError(f"Invalid image value: {packet_l[4]}")
            image: Literal['True', 'False'] = cast(Literal['True', 'False'], packet_l[4])

            logger.debug(packet_l[5])
            packet_dict: ServerRequest = {
                "method": method,
                "url": packet_l[1],
                "headers": json.loads(packet_l[2]),
                "parameters": packet_l[3],
                "image": image,
                "cookies": json.loads(packet_l[5]),
                "session": packet_l[6],
                "heartbeat": packet_l[7]
            }
        except Exception as e:
            logger.warning(traceback.format_exc())
            raise ValueError(f"Corrupted: {str(e)}") from e

        return packet_dict

    async def encrypt(self, response: ServerResponse) -> bytes:
        cookies = response["cookies"].encode("utf-8")
        code = str(response["code"]).encode("utf-8")
        source = response["source"].encode("utf-8")
        content_type = response["content_type"].encode("utf-8")
        logger.debug(cookies)

        header = (
            str(len(code)).zfill(2)
            + str(len(content_type)).zfill(2)
            + str(len(source)).zfill(9)
            + str(len(cookies)).zfill(5) #18
        ).encode("utf-8")

        packet = header + code + content_type + source + cookies
        # expected_hmac = hmac.new(self.init.secret, packet, hashlib.sha256).digest()
        checksum = hashlib.sha256(packet).digest()
        b64_checksum = base64.b64encode(checksum)
        comp_packet = zlib.compress(packet)
        if b'\0\0\0\xFF\xFF\xFF\0\0\0' in comp_packet:
            raise MessageFormatingError("Misplaced end marker")
        if len(cookies) > 9999:
            logger.critical("Cookies are too long!")
            self.init.terminated()

        packet = b64_checksum + comp_packet + b"\0\0\0\xFF\xFF\xFF\0\0\0"

        return packet

    async def writer_close_task(self, writer: StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except ConnectionResetError:
            logger.debug("Connection reset by peer during writer.wait_closed()")
        except Exception as e:
            logger.warning("Unexpected exception [%s]", str(e))

    async def _cancel_task(self, task: asyncio.Task[Any]) -> None:
        try:
            logger.debug(f"Cancelling {task}")
            task.cancel()
            await task
        except asyncio.CancelledError:
            pass
            # logger.debug("%s was cancelled.", str(task))
        except Exception as e:
            logger.warning(e)

    async def server_shutdown_task(self) -> None:
        logger.debug("ProxyServer shutting down.")
        try:
            self.server.close()
            await self.server.wait_closed()  # wait until all existing connections are closed
            self.server_task.cancel()
            await self.server_task
            logger.debug("Server closed.")
        except AttributeError as e:
            logger.debug("Sever not started? %s", str(e))
        except asyncio.CancelledError:
            logger.debug("Server serve_forever() task cancelled.")

    async def shutdown(self) -> None:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self.server_shutdown_task())

            for conn in self.connections.values():
                tg.create_task(self._cancel_task(conn))

            if hasattr(self, 'session_manager'):
                tg.create_task(self.session_manager.shutdown_sessions())
                logger.debug('session_manager shutdown')

class DriverlessHandle:
    def __init__(self, stats: Stats, drivenbrowser: weakref.ProxyType[DrivenBrowser], requestid: int, timeout: float) -> None:
        self.stats: Stats = stats
        self.drivenbrowser: DrivenBrowser = drivenbrowser
        self.requestid: int = requestid
        self.timeout: float = timeout

        self.img_workaround: bool = False

    async def cloudflare_captcha_checked(self, tab: Target) -> bool:
        try:
            await tab.find_element(
                By.XPATH,
                """//input[@type='hidden' and starts-with(@id, 'cf-chl-widget-') and substring(@id, string-length(@id) - string-length('_response') + 1) = '_response']/..""",
                timeout=3,
            )
        except NoSuchElementException:
            return True

        for q in range(1,3):
            logger.info("Cloudflare present.")

            if q > 1:
                await asyncio.sleep(random.uniform(1.1, 2.8))
            else:
                await asyncio.sleep(random.uniform(5.1, 8.2))

            try:
                container = await tab.find_element(
                    By.XPATH,
                    """//input[@type='hidden' and starts-with(@id, 'cf-chl-widget-') and substring(@id, string-length(@id) - string-length('_response') + 1) = '_response']/..""",
                    timeout=2,
                )
            except Exception as e:
                logger.debug(e)
                continue

            try:
                shadow_document: Optional[WebElement] = await container.shadow_root
                if not shadow_document:
                    raise NoSuchElementException()
                iframe: WebElement = await shadow_document.find_element(By.CSS_SELECTOR, "iframe", timeout=3)
                await iframe.scroll_to()
                content_document: WebElement = await asyncio.wait_for(iframe.content_document, timeout=10)
                body: WebElement = await content_document.find_element(By.CSS_SELECTOR, "body", timeout=2)
                nested_shadow_document: Optional[WebElement] = await body.shadow_root
                if not nested_shadow_document:
                    raise NoSuchElementException()
                checkbox: WebElement = await nested_shadow_document.find_element(By.CSS_SELECTOR, "input[type='checkbox']", timeout=10)
            except Exception as e:
                logger.warning("Failed to locate the elements: [%s]", str(e))
                break

            try:
                for _ in range(6):
                    text: WebElement = await checkbox.find_element(By.XPATH, "..", timeout=1)
                    logger.debug("Text %s", await text.text)
                    if await text.text == "Verify you are human":
                        break
                else:
                    return False

                logger.info("Clicked")
                frame_rect: dict[str, int] = await iframe.rect
                cords: list[int] = await checkbox.mid_location()
                x: int = frame_rect["x"] + cords[0]
                y: int = frame_rect["y"] + cords[1]
                #logger.debug((x, y))
                await tab.focus(activate=True)
                #await asyncio.sleep(0.5)
                #await tab.get_screenshot_as_file('/home/r/Downloads/png1.png')

                await tab.pointer.click(x_or_elem=x, y=y)

                current_text: str = "None"
                for _ in range(8):
                    # await tab.get_screenshot_as_file('/home/r/Downloads/png2.png')
                    current_text = await text.text
                    logger.debug(current_text)
                    if current_text not in ("Verifying...", "Verify you are human"):
                        break
                    await asyncio.sleep(0.5)

                if current_text in ("Verifying...", "Verify you are human"):
                    await tab.pointer.click(x_or_elem=x, y=y)
                    await asyncio.sleep(0.3)
                    # await tab.get_screenshot_as_file('/home/r/Downloads/png3.png')
                    logger.error('Failed to click captcha')

                for _ in range(5):
                    await tab.find_element(
                        By.XPATH,
                        """//input[@type='hidden' and starts-with(@id, 'cf-chl-widget-') and substring(@id, string-length(@id) - string-length('_response') + 1) = '_response']""",
                        timeout=1,
                    )
                    await asyncio.sleep(1)

            except TimeoutError as e:
                logger.warning("Couldn't locate an element in time (%s)", str(e))
            except NoSuchElementException:
                logger.debug("Captcha is gone?")
            except Exception as e:
                logger.debug(e)
            finally:
                await asyncio.sleep(random.randint(1, 3))
                await tab.refresh()
                await self.page_loaded(tab)

            try:
                await tab.find_element(
                    By.XPATH,
                    """//input[@type='hidden' and starts-with(@id, 'cf-chl-widget-') and substring(@id, string-length(@id) - string-length('_response') + 1) = '_response']/..""",
                    timeout=1,
                )
            except NoSuchElementException:
                return True
            except TimeoutError as e:
                logger.error(e)

            if q > 1:
                return False
        else:
            return True
        return False

    async def yandex_captcha_checked(self, tab: Target) -> bool:
        await tab.refresh()
        await self.page_loaded(tab)
        try:
            iframe = await tab.find_element(By.XPATH, '//*[@id="checkbox-captcha-form"]/div[3]/div/iframe', timeout=6)
            iframe_rect = await iframe.rect
            iframe_content = await iframe.content_document
            div_button = await iframe_content.find_element(By.XPATH, '//div[@class="CheckboxCaptcha-Anchor" and input[@id="js-button"]]', timeout=6)
            #button = await iframe_content.find_element(By.XPATH, '//div[@class="CheckboxCaptcha-Anchor"]/input[@id="js-button"]')
        except Exception as e:
            await tab.get_screenshot_as_file("/home/x/Downloads/2.png")
            raise e
        x, y = await div_button.mid_location()
        iframe_rect["x"] += x
        iframe_rect["y"] += y
        logger.debug((iframe_rect["x"], iframe_rect["y"]))
        await tab.focus(activate=True)
        await tab.pointer.click(x_or_elem=int(iframe_rect["x"]), y=int(iframe_rect["y"]))
        try:
            tries: int = 0
            while await tab.find_element(By.XPATH, '//span[@class="Text Text_weight_medium Text_typography_headline-s"]', timeout=3) and tries < 6:
                logger.debug(await tab.find_element(By.XPATH, '//span[@class="Text Text_weight_medium Text_typography_headline-s"]'))
                await asyncio.sleep(1)
                tries += 1
        except NoSuchElementException:
            return True
        return False

    async def is_captcha(self, tab: Target, code: int) -> bool:
        await self.page_loaded(tab)
        try:
            checkbox = await tab.find_element(
                By.XPATH,
                """//input[@type='hidden' and starts-with(@id, 'cf-chl-widget-') and substring(@id, string-length(@id) - string-length('_response') + 1) = '_response']/..""",
                timeout=10
            )
        except Exception as e:
            logger.debug("No captcha (%s)", str(e))
            return False

        if code == 403 or checkbox:
            if await self.cloudflare_captcha_checked(tab):
                logger.debug("Captcha is gone")
            else:
                logger.error('Failed to solve captcha')
            return True
        return False

    async def page_loaded(self, tab: Target) -> None:
        state: str = "None"
        try:
            state = await tab.eval_async("return document.readyState")
            logger.debug(state)
            for x in range(100):
                if state == "complete":
                    break
                state = await tab.eval_async("return document.readyState")
                await asyncio.sleep(0.2)
                logger.debug((state, x))
        except TimeoutError:
            logger.warning("Timeout!")
        if state != "complete":
            logger.warning("Page failed to load in time")

    async def driverless_post(self, path: str, headers: dict[str, str], params: str, tab: Target) -> tuple[int, str, bytes, str]:
        # Tested only on inkbunny & AO3
        logger.debug("POST URL: %s", path)
        #urllib_wantedurl: urllib.parse.SplitResult = urllib.parse.urlsplit(path)
        #await tab.get("https://" + str(urllib_wantedurl[1]), wait_load=True)
        await tab.get(path, wait_load=True)

        await self.page_loaded(tab)
        # AO3 does not respond with the elements that indicate that user has logged in.
        # await tab.execute_cdp_cmd("Network.clearBrowserCache")

        if "Content-Type" in headers:
            logger.debug("Raw params")
            logger.debug(params)

        headers['Content-Type'] = "application/x-www-form-urlencoded"
        params_dict: dict[str, str] = json.loads(params)
        encoded_params: str = urllib.parse.urlencode(params_dict)

        headers['Referer'] = path

        javascript_code = f"""
                try {{
                    const response = await fetch('{path}', {{
                        method: 'POST',
                        headers: {json.dumps(headers)},
                        body: '{encoded_params}'
                    }});
                    const contentType = response.headers.get('content-type') || 'Unknown';
                    const body = await response.text();
                    const result = {{
                        statusCode: response.status,
                        statusText: response.statusText,
                        contentType: contentType,
                        body: body,
                        responseURL: response.url,
                        readyState: 4
                    }};
                    return JSON.stringify(result);
                }} catch (error) {{
                    const errorResult = {{
                        statusCode: 0,
                        statusText: 'JavaScript Error',
                        contentType: 'text/plain',
                        body: error.toString(),
                        responseURL: '',
                        readyState: 0
                    }};
                    return JSON.stringify(errorResult);
                }}
        """

        raw_response = await tab.eval_async(javascript_code, timeout=self.timeout)
        response: dict[str, str] = json.loads(raw_response)
        status_code: int = int(response["statusCode"])
        content_type: str = str(response["contentType"].split(";", 1)[0])
        source: bytes = response["body"].encode('utf-8')

        if status_code < 200 or status_code >= 300:
            logger.debug('PostExcp')

        logger.info("POST returned: '%s'", str(status_code))
        logger.info("POST returned: '%s'", response["responseURL"])
        logger.info("POST type: '%s'", content_type)

        return status_code, content_type, source, "None"

    def condition_url(self, url: str, old: str) -> list[str]:
        split_url = urllib.parse.urlparse(url)
        split_old = urllib.parse.urlsplit(old)
        netloc = split_url.netloc or split_old.netloc
        path = split_url.path
        params = split_url.params
        query = split_url.query
        fragment = split_url.fragment

        https_url = urllib.parse.urlunparse(("https", netloc, path, params, query, fragment))
        http_url = urllib.parse.urlunparse(("http", netloc, path, params, query, fragment))
        https_url_part = urllib.parse.urlunparse(("https", netloc, path, params, query, ""))
        http_url_part = urllib.parse.urlunparse(("http", netloc, path, params, query, ""))

        logger.debug([https_url, http_url, https_url_part, http_url_part])
        return [https_url, http_url, https_url_part, http_url_part]

    async def correct_image_content(self, url: str, status_code: int, content_type: str, source: bytes) -> tuple[Optional[str], str]:
        def check(pattern: bytes) -> Optional[str]:
            link = re.search(pattern, source, flags=re.DOTALL)
            if link:
                new_url: str = (link.group(1)).decode()
                logger.info(f"Changing '{url}' -> '{new_url}'")
                return new_url
            return None
        new_url = None
        # Dropbox just starts a download and returns application/binary content type but the picture is still in the req
        # https://www.giantbomb.com/a/uploads/scale_medium/8/87790/2549843-box_gawg3.png returns application/octet-stream
        # https://archiveofourown.org/works/61648471
        # https://lh7-us.googleusercontent.com/dkCfjI5hFIchFj3S4mGHpGaPbYUp74BgONfz1OvlDee9STw-QUzNvkAMha7z8MNSf-uo_WBIhiLE4QNYQgzO00HZPePqVq6uVn5S-6EdtX3soEFhiaceY0ryzi6Lj-MojxrxFIFTcIRZ9gaN39rAkaI
        if content_type in ('application/binary', 'application/octet-stream'):
            logger.debug("%s => image/", content_type)
            logger.debug(source[:20])
            content_type = 'image/binary_octet-stream'
        # Returns content type PNG32 https://f2.toyhou.se/file/f2-toyhou-se/images/98977002_zdtNOHleL0fI9Nq.png
        # Returns content type JPEG 'http://f2.toyhou.se/file/f2-toyhou-se/images/99141478_dszVOhMBtrb3oWq.jpg'
        if content_type == 'PNG32':
            content_type = 'image/png'
        if content_type == 'JPEG':
            content_type = 'image/jpeg'
        # I can't get the imgur to respond with a picture.
        # Raw pictures are not being returned at 'imgur.com'.; the 'i.imgur.com' link needs to be extracted.
        # The same can be said about imgbox.com
        if content_type == 'text/html':
            netloc = urllib.parse.urlsplit(url).netloc
            if netloc == 'imgur.com':
                new_url = check(br'<meta name=\"twitter:image\" data-react-helmet=\"true\" content=\"(.+?)\"><link rel=\"alternate\" type=\"application/json\+oembed\"')
            elif netloc == 'imgbox.com':
                new_url = check(br'<meta property=\"og:image\" content=\"(.+?)\"/>')
            elif netloc == 'postimg.cc':
                new_url = check(br'<meta property=\"og:image\" content=\"(.+?)\">')
            elif netloc == 'rule34.xxx':
                new_url = check(br'Resize image.+?<a href=\"(http.+?)\"')
            elif netloc.startswith("furry34com"):
                raise RefererError("Removing referer")
            elif 'pinterest.com' in netloc:
                new_url = check(br'<link as="image" fetchPriority="high" href="(.+?)" ')

        if not self.img_workaround:
            if not content_type.lower().startswith('image') and not status_code == 404:
                raise ImageError(content_type, (status_code, content_type, source, "Not an image"))
            # This is for https://static.wikia.nocookie.net/walkthrough/images/3/3c/Link_On_Mario_Bros_stage.png/revision/latest?cb=20100316231141
            # As including the referer causes the website to return 404
            if urllib.parse.urlsplit(url).netloc == "static.wikia.nocookie.net" and status_code == 404:
                raise RefererError("Removing referer")

        return new_url, content_type

    async def driverless_get(self, tab: Target, url: str, image: Literal["True", "False"], headers: dict[str, str]) -> tuple[int, str, bytes, str]:
        referer: Optional[str] = headers.get('Referer')
        old = url
        content_type = "None"
        status_code = -10
        source: bytes = b"Failed"
        # For the infinite redirection https://archiveofourown.org/works/38595468
        redirects = 0
        error: str = "None"
        response_headers = None
        req: Optional[asyncio.Future[dict[str,str]]] = None

        while True:
            download_started = asyncio.Event()
            download_started_task: asyncio.Task[Optional[DownloadWillBeginParams]] = asyncio.create_task(self.drivenbrowser.listen_for_download(tab, download_started))

            links = self.condition_url(url, old)

            self.drivenbrowser.mitm_instance.set_response_header_rule(set(links),[])
            if image == "True":
                self.drivenbrowser.mitm_instance.set_request_header_rule(set(links),
                    [('Sec-Fetch-Dest', 'image'), ('Sec-Fetch-Mode', 'no-cors'), ('Sec-Fetch-Site', 'cross-site'),
                    ('Accept', 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8'), ('Priority', 'u=2, i')])
            else:
                self.drivenbrowser.mitm_instance.set_request_header_rule(set(links), [('Sec-Fetch-User', '?1')])

            try:
                logger.info("URL: %s | Referer: %s", links[0], str(referer))

                async with self.drivenbrowser.mitm_instance.intercept(links) as cap:
                    req = asyncio.ensure_future(tab.get(links[0], referrer=referer, wait_load=False, timeout=self.timeout))
                    async for resp in cap:
                        status_code = resp.status_code
                        source = resp.body
                        content_type = resp.content_type.split(";", 1)[0]
                        response_headers = resp.headers
                        if resp.error is not None:
                            logger.warning("Proxy error 502 [%s]: %s", resp.error.code, resp.error.message)
                            error = resp.error.code
                        if redirects > 7:
                            status_code = 500
                            error = "Too Many Redirects"
                        break

                if download_started.is_set():
                    logger.debug("Download will begin")
                    params = await download_started_task
                    if not params:
                        logger.error("Download started but no params!")
                        raise Exception("No params")
                    async for event in self.drivenbrowser.wait_for_download_completion(tab, params["guid"]):
                        logger.info(f"Download {event['state']} [{event.get('receivedBytes',0)}/{event.get('totalBytes',0)}]")
                        if file := event.get('filePath', ''):
                            with open(file, "rb") as file_source:
                                source = file_source.read()
                            os.remove(file)
                            return 200, "image/file", source, "File"

                if not (400 <= status_code < 500):
                    try:
                        await tab.execute_cdp_cmd("Page.stopLoading", {})
                        logger.debug("Page stopped")
                    except Exception as e:
                        logger.debug("Stop error %s", str(e))

            except CDPError as e:
                logger.warning(e)
                if not (e.code == -32602 and e.message == 'Invalid InterceptionId.'):
                    raise e
            except Exception as e:
                logger.warning(e)
                raise e from None
            finally:
                try:
                    download_started_task.cancel()
                    await download_started_task
                except asyncio.CancelledError:
                    pass
                if req is not None:
                    try:
                        req.cancel()
                        await req
                    except asyncio.CancelledError:
                        pass
                    except Exception as e:
                        logger.debug(e)
                    req = None
                if image == "True":
                    self.drivenbrowser.mitm_instance.remove_request_header_rule()

            if error != "None":
                return status_code, content_type, source, error

            logger.info("Page returned: '%s'", str(status_code))
            if status_code in [299, 301, 302, 303, 307, 308] and response_headers:
                old = links[0]
                for header in response_headers:
                    if header[0].decode().lower() == 'location':
                        url = header[1].decode()
                        redirects += 1
                        logger.debug("Redirect [%s]", url)
                        break
                continue

            if image == "True" and not content_type:
                # 'https://fbi.cults3d.com/uploaders/15065999/illustration-file/394535b8-90c7-463c-a14a-d963a7b052dc/Brigthcrest.jpg'
                logger.warning('No content type! Assume image.')
                content_type = "image/None"

            if status_code == -10 or not content_type or not response_headers:
                logger.debug(response_headers)
                if not self.img_workaround:
                    raise ImageError("Did not get headers", (-1, "None", b"None", "Did not get headers"))
                status_code = -1
                return status_code, "None", b"None", f"Could not get a full response ({headers})"

            if image == "True":
                new_url, content_type = await self.correct_image_content(url, status_code, content_type, source)
                if new_url:
                    url = new_url
                    continue

            break

        logger.info("Page returned: '%s'", content_type)

        return status_code, content_type, source, error

    async def fetch(self, request: ServerRequest) -> ServerResponse:
        result: tuple[int, str, bytes, str] = (-1, "None", b"None", "Failed to get a page.")

        tab, drivenbrowser_id = await self.drivenbrowser.get_tab(self.requestid)

        if request["cookies"]:
            logger.debug("We got extra cookies")
            await asyncio.gather(*(tab.add_cookie(cookie) for cookie in request["cookies"]))

        attempt = 0
        while attempt < 4:
            attempt += 1
            logger.info("Attempt %s for %s [%s]", str(attempt), request['session'], request["url"])
            try:
                if request["method"] == "GET":
                    result = await asyncio.wait_for(self.driverless_get(tab=tab, url=request["url"], headers=request["headers"], image=request["image"]),
                                                    timeout=self.timeout*1.2)
                elif request["method"] == "POST":
                    result = await asyncio.wait_for(self.driverless_post(tab=tab, path=request["url"], headers=request["headers"], params=request["parameters"]),
                                                    timeout=self.timeout*1.2)
                else:
                    logger.error("Not supported HTTP method: %s", request["method"])
                    return {"code": -1, "content_type": "None", "source": "RmFpbGVk", "cookies": "None", "errors": "Not supported HTTP method"}
            except TimeoutError:
                logger.warning("TimeoutError at content: %s", result[3])
                await self.drivenbrowser.destroy_tab(self.requestid)
                tab, drivenbrowser_id = await self.drivenbrowser.get_tab(self.requestid)
                continue
            except ImageError as e:
                logger.debug("Image Error: %s", str(e))
                self.img_workaround = True
                result = e.response
                await self.is_captcha(tab, result[0])
                continue
            except RefererError:
                logger.debug("Removing ref")
                self.img_workaround = True
                request["headers"].pop('Referer', None)
                continue
            except ConnectionClosedError:
                logger.warning("Chrome exception, recovery attempt.")
                await self.drivenbrowser.broken_browser(drivenbrowser_id)
                tab, drivenbrowser_id = await self.drivenbrowser.get_tab(self.requestid)
                continue

            if result[0] == 525:
                continue

            if result[3] == ProxyError.NAME_NOT_RESOLVED:
                break
            elif result[3] == ProxyError.TTL_EXPIRED:
                await self.drivenbrowser.set_socks_proxy("ch-zrh-wg-socks5-503.relays.mullvad.net:1080")
                continue

            if result[0] != 404 and 400 < result[0] < 500:
                page_title = await tab.title
                if 'used Cloudflare to restrict hotlinking' in page_title:
                    logger.debug(page_title)
                    request['headers']['Referer'] = request['url']
                    continue

                if not await self.is_captcha(tab, result[0]) and attempt > 0:
                    break
                continue
            break
        else:
            logger.warning("Failed to get the content. Sending as is!")

        if result[0] not in [200, 404]:
            if request["image"] == "True" and not result[1].lower().startswith('image'):
                logger.warning("Failed to get an image!")
                self.stats.add_failed(request["url"], f"Failed to fetch the image {result[0]}")
            else:
                self.stats.add_failed(request["url"], f"{str(result[0])}: {result[3]}")

        out_cookies: str = "None"
        raw_cookies: list[ResponseCookie] = await self.drivenbrowser.get_cookies()
        if raw_cookies:# and request["image"] == "False":
            out_cookies = json.dumps(raw_cookies)
        logger.debug(out_cookies)

        return {"code": result[0], "content_type": result[1], "cookies": out_cookies, "source": base64.b64encode(result[2]).decode(), "errors": result[3]}

class CffiHandle:
    def __init__(self, cffi: weakref.ProxyType[CffiFetcher], stats: Stats, timeout: float) -> None:
        self.cffi_fetcher: CffiFetcher = cffi
        self.timeout: float = timeout
        self.stats: Stats = stats

    @staticmethod
    def cookiejar_to_dict(jar: CookieJar) -> list[ResponseCookie]:
        return [ResponseCookie(
                    name = c.name,
                    value = c.value or "",
                    domain = c.domain,
                    path = c.path,
                    expires = c.expires if c.expires is not None else -1,
                    size = len(c.name) + len(c.value or ""),
                    secure = c.secure,
                    httpOnly = c._rest.get("HttpOnly", False),
                    sameSite = c._rest.get("SameSite"),
                    session = c.discard)
                for c in jar
                ]

    @staticmethod
    def to_cookie(c: RequestCookie) -> Cookie:
        expires = c["expires"]
        if expires in (-1, 0):
            expires = None

        rest: dict[str, str | None] = {}
        if c["httpOnly"]:
            rest["HttpOnly"] = None

        return Cookie(
            version=0,
            name=c["name"],
            value=c["value"],
            port=None,
            port_specified=False,
            domain=c["domain"],
            domain_specified=bool(c["domain"]),
            domain_initial_dot=c["domain"].startswith("."),
            path=c["path"],
            path_specified=bool(c["path"]),
            secure=c["secure"],
            expires=expires,
            discard=False,
            comment=None,
            comment_url=None,
            rest=rest,
            rfc2109=False,
        )

    async def get(self, request: ServerRequest, session: AsyncSession) -> ServerResponse:
        logger.info(f"Cffi GET {request["url"]}")

        proxy: Optional[ProxySpec] = None
        if socks_address := self.cffi_fetcher.get_current_socks_proxy():
            proxy = {"all": "socks://"+socks_address}

        headers = {"sec-ch-ua": None, "sec-ch-ua-mobile": None, "sec-ch-ua-platform": None, "user-agent": self.cffi_fetcher.chromes_user_agent}
        if ref := request["headers"].get('Referer'):
            headers['Referer'] = ref

        try:
            response = await session.get(request["url"],
                                        headers=headers,
                                        proxies=proxy,
                                        impersonate="chrome133a")
        except Exception as e:
            logger.debug(str(e))
            if "(56) Connection closed abruptly" in str(e):
                return {"code": 0, "content_type": "None/None", "cookies": "None", "source": base64.b64encode(b"Err").decode(), "errors": "ConnClosed"}
            raise e

        out_cookies = json.dumps(self.cookiejar_to_dict(session.cookies.jar))

        if response.headers.get("cf-mitigated", "").lower() == "challenge":
            return {"code": response.status_code, "content_type": response.headers.get("content-type"), "cookies": out_cookies, "source": base64.b64encode(response.content).decode(), "errors": "Cloudflare"}

        return {"code": response.status_code, "content_type": response.headers.get("content-type"), "cookies": out_cookies, "source": base64.b64encode(response.content).decode(), "errors": ""}

    async def post(self, request: ServerRequest, session: AsyncSession) -> ServerResponse:
        params: dict[str, str] = json.loads(request["parameters"])
        logger.info(f"Cffi POST {request["url"]}")

        headers = {'Referer': request["url"], "sec-ch-ua": None, "sec-ch-ua-mobile": None, "sec-ch-ua-platform": None, "user-agent": self.cffi_fetcher.chromes_user_agent}

        response = await session.post(request["url"], headers=headers, impersonate="chrome133a", data=params)

        out_cookies = json.dumps(self.cookiejar_to_dict(session.cookies.jar))
        logger.debug(response.headers)
        if response.headers.get("cf-mitigated", "").lower() == "challenge":
            return {"code": response.status_code, "content_type": response.headers.get("content-type"), "cookies": out_cookies, "source": base64.b64encode(response.content).decode(), "errors": "Cloudflare"}

        return {"code": response.status_code, "content_type": response.headers.get("content-type"), "cookies": out_cookies, "source": base64.b64encode(response.content).decode(), "errors": ""}

    async def fetch(self, request: ServerRequest) -> ServerResponse:
        session = await self.cffi_fetcher.get_browser()
        jar_cookies = [self.to_cookie(c) for c in request["cookies"]]
        for ck in jar_cookies:
            logger.debug(f"Adding {ck}")
            session.cookies.jar.set_cookie(ck)

        if request["method"] == "GET":
            response = await self.get(request=request, session=session)
        elif request["method"] == "POST":
            response = await self.post(request=request, session=session)
        else:
            raise Exception("Not supported HTTP method")

        if response["errors"] == "ConnClosed":
            return await self.fetch(request=request)
        
        logger.debug(response["cookies"])

        if response["code"] not in [200, 404]:
            if request["image"] == "True" and not response["content_type"].lower().startswith('image'):
                logger.warning("Failed to get an image!")
                self.stats.add_failed(request["url"], f"Failed to fetch the image {response["code"]}")
            logger.debug(f"Cffi err {response["errors"]}")
            # else:
            #     self.stats.add_failed(request["url"], f"{str(response["code"])}: {response["errors"]}")

        return response

class ClientRequest:
    def __init__(self, stats: Stats, session: Session) -> None:
        self.stats: Stats = stats
        self.session: Session = session
        self.timeout: float = 60.0

    async def main(self, request: ServerRequest) -> ServerResponse:
        result: ServerResponse = {"code": -1, "content_type": "None", "cookies": r"{}", "source": base64.b64encode(b"Failed to get a page.").decode(), "errors": ""}
        reqid = random.randint(-100000, 100000)

        try:
            result = await CffiHandle(self.session.weak_fetcher, self.stats, self.timeout).fetch(request)
            if not result["errors"] == "Cloudflare":
                return result
            else:
                logger.warning("Cloudflare "+request["session"])
        except Exception as e:
            logger.warning(e)

        result = await DriverlessHandle(self.stats, self.session.weak_browser, reqid, self.timeout).fetch(request)
        await self.session.weak_browser.destroy_tab(reqid, self.session.in_use)

        return result

logger = logging.getLogger(__name__)
# logger.propagate = False
# Create console handler
ch: logging.StreamHandler[TextIO] = logging.StreamHandler()
# Create formatter and add it to the handler
formatter: ColoredFormatter = ColoredFormatter('%(elapsed)s | %(levelname)-8s | %(filename)s | %(funcName)s[%(lineno)d] | %(message)s')
ch.setFormatter(formatter)
# Add the handler to the logger
root_logger = logging.getLogger()
root_logger.addHandler(ch)
root_logger.setLevel(logging.WARNING)

parser = argparse.ArgumentParser(description="SeleniumServer")
parser.add_argument('-c','--config', type=str, metavar='PATH', default='./config.ini', help="Path to config")
parser.add_argument('-d','--debug', dest='debug', action='store_true', help='Show debug log')
parser.add_argument('-t','--trace', dest='trace', action='store_true', help=argparse.SUPPRESS)

parser.add_argument("--xvfb", dest='xvfb', action=argparse.BooleanOptionalAction, default=None, help="Enable or disable Xvfb")
parser.add_argument('--host', dest='host', type=str, metavar='HOST', default=None, help='Host/IP to bind (default: localhost)')
parser.add_argument('--port', dest='port', type=int, metavar='PORT', default=None, help='Port to listen on (default: 23000)')
parser.add_argument('--no-verify-ssl', dest='verify_ssl', action='store_false', help='Disable SSL cert verification')

parser.add_argument('--cert', dest='cert', type=str, metavar='PATH', help='Path to server TLS certificate (PEM)')
parser.add_argument('--key', dest='key', type=str, metavar='PATH', help='Path to server TLS private key (PEM)')
parser.add_argument('--cacert', dest='cacert', type=str, metavar='PATH', help='Path to CA certificate for client verification (PEM)')

parser.add_argument('--chrome', dest='chrome', type=str, metavar='PATH', help='Path to Chromium/Chrome executable')
parser.add_argument('--ublock', dest='ublock', type=str, metavar='PATH', help='Path to extension file')
parser.add_argument('--driver-timeout', dest='driver_timeout', type=int, metavar='SECONDS', default=None, help='Time in seconds to close Chrome after last request (default: 60)')

parser.add_argument('--mitm-key', dest='mitm_ca_key', type=str, metavar='PATH', help=argparse.SUPPRESS)
parser.add_argument('--mitm-cert', dest='mitm_ca_cert', type=str, metavar='PATH', help=argparse.SUPPRESS)

parser.add_argument('--impersonate', dest='impersonate_chrome', type=str, default='', help=argparse.SUPPRESS)

handler: Callable[[BaseException], None] = (lambda e: logger.debug(f'Event-handler: {e.__class__.__name__}: {str(e)}'))
sys.modules["selenium_driverless"].EXC_HANDLER = handler
sys.modules["cdp_socket"].EXC_HANDLER = handler

if __name__ == "__main__":
    try:
        args: argparse.Namespace = parser.parse_args()
        Init().prepserver()
    except Exception:
        logger.critical('Failed to initialize %s', str(traceback.format_exc()))
    finally:
        sys.exit(0)
