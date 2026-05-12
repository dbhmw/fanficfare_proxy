from __future__ import annotations
import uvloop
uvloop.install()
import patch_func
from patch_func import _clear_frames

from typing import Optional, Literal, Any, TypedDict, TextIO, cast, Callable, AsyncGenerator, NotRequired
import asyncio, zlib, argparse, configparser, sys, signal, logging
import ssl, base64, hashlib, json, re, threading
import weakref
import tempfile
from xvfbwrapper import Xvfb
from asyncio.sslproto import SSLProtocol
from asyncio import StreamReader, StreamWriter, StreamReaderProtocol
from functools import partial

from selenium_driverless import webdriver
from selenium_driverless.types.by import By
from selenium_driverless.types.target import Target
from selenium_driverless.types.context import Context
from selenium_driverless.types.webelement import NoSuchElementException, WebElement
from cdp_socket.exceptions import CDPError
from websockets.exceptions import ConnectionClosedError

# All of this shit just to get a plain png out of the websites
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

from mitm_proxy import (
    SessionProxy,
    SocksProxyPool,
    ProxyConfig,
    SidecarManager,
    set_sidecar_log_level,
    set_proxy_log_level)

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

class SessionData(TypedDict):
    StaleCheck: asyncio.Task[None]
    DrivenBrowser: DrivenBrowser

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

class ResponseCookie(TypedDict, total=False):
    name: str
    value: str
    domain: str
    path: str
    expires: int
    size: int
    httpOnly: bool
    secure: bool
    session: bool
    sameSite: str
    priority: str
    sameParty: bool
    sourceScheme: str
    sourcePort: int
    partitionKey: CookiePartitionKey
    partitionKeyOpaque: bool

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

class OutdatedUrlError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)

class ColoredFormatter(logging.Formatter):
    RESET: str = "\033[0m"
    DEBUG: str = "\033[2;34m"
    INFO: str = "\033[34m"
    WARNING: str = "\033[1;33m"
    ERROR: str = "\033[1;31m"
    CRITICAL: str = "\033[1;37;41m"

    def format(self, record: logging.LogRecord) -> str:
        def get_color(levelno: int) -> str:
            if levelno == logging.DEBUG:
                return ColoredFormatter.RESET
            if levelno == logging.INFO:
                return ColoredFormatter.INFO
            if levelno == logging.WARNING:
                return ColoredFormatter.WARNING
            if levelno == logging.ERROR:
                return ColoredFormatter.ERROR
            if levelno == logging.CRITICAL:
                return ColoredFormatter.CRITICAL
            return ColoredFormatter.RESET

        colour = get_color(record.levelno)
        elapsed_seconds = record.relativeCreated / 1000.0
        record.elapsed = f"{elapsed_seconds:8.3f}"
        # record.asctime = self.formatTime(record, datefmt='%Y-%m-%d %H:%M:%S,%f')[:-3]  # Keep only milliseconds
        record.msg = f"{colour}{record.msg}{ColoredFormatter.RESET}"
        record.levelname = f"{colour}{record.levelname:<8}{ColoredFormatter.RESET}"

        return super().format(record)

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
        self.browsercontroller: BrowserController
        self.server_task: asyncio.Task[None]

        self.init: Init = init
        self.stats: Stats = self.init.statistics
        self.connections: dict[bytes,asyncio.Task[None]] = {}

    async def run_server(self, loop: asyncio.AbstractEventLoop) -> None:
        try:
            self.browsercontroller = await BrowserController.initialize(self.init)

            context: ssl.SSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(
                certfile=self.init.cert,
                keyfile=self.init.key,
            )
            context.load_verify_locations(cafile=self.init.client_cert)

            def connection(reader: StreamReader, writer: StreamWriter) -> None:
                client = loop.create_task(self.handle_client(reader, writer))
                client_id = os.urandom(32)
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

        logger.info("Serving FFF proxy on %s", self.server.sockets[0].getsockname())

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

        try:
            if request["session"] == "None":
                _drivenbrowser, drivenbrowser_ref = await self.browsercontroller.get_temp_browser(request["session"])
            else:
                logger.debug("Client %s: Request for browser enqueued.", request["session"])
                drivenbrowser_ref = await self.browsercontroller.get_session_browser(request["session"])
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("Failed to get browser")
            await self.send_response(writer, await self.encrypt(response=content))
            raise e

        try:
            heartbeat = asyncio.create_task(self.heartbeat(writer, request["heartbeat"]))
            reqid = random.randint(-100000, 100000)
            try:
                client = ClientRequest(self.stats, drivenbrowser_ref, reqid)
                weakref.finalize(client, lambda: logger.debug("Garbage collected client"))
                client_task = asyncio.create_task(client.main(request))
                drivenbrowser_ref.in_use += 1
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
                if request["session"] == "None":
                    await drivenbrowser_ref.terminate_session()
                    del _drivenbrowser
                else:
                    drivenbrowser_ref.last_used = time.time()
                    drivenbrowser_ref.in_use -= 1
                    await drivenbrowser_ref.destroy_tab(reqid)
                if client:
                    logger.debug(sys.getrefcount(client))
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
            for conn in self.connections.values():
                tg.create_task(self._cancel_task(conn))

            tg.create_task(self.server_shutdown_task())

            if hasattr(self, 'browsercontroller'):
                tg.create_task(self.browsercontroller.shutdown_sessions())
                logger.debug('browsercontroller shutdown')

class ProxyLoop:
    """Singleton background thread + event loop for all SessionProxy instances."""
    _instance: Optional[ProxyLoop] = None
    _lock = threading.Lock()

    @classmethod
    def get(cls) -> ProxyLoop:
        if cls._instance is not None and cls._instance.is_alive():
            logger.debug("ProxyLoop already created")
            return cls._instance

        with cls._lock:
            # Second check — another thread may have created it while
            # we were waiting for the lock
            if cls._instance is not None and cls._instance.is_alive():
                logger.debug("ProxyLoop already created by another thread")
                return cls._instance

            if cls._instance is not None:
                logger.warning("ProxyLoop was dead, recreating (thread=%s, loop_closed=%s)",
                            cls._instance._thread.is_alive(),
                            cls._instance.loop.is_closed())
            else:
                logger.debug("ProxyLoop first-time creation")

            _instance = cls()
            cls._instance = _instance
            return _instance

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="SharedProxyLoop"
        )
        self._thread.start()
        logger.info("ProxyLoop thread started (tid=%d, thread=%s)",
                     self._thread.ident, self._thread.name)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        logger.debug("ProxyLoop event loop running")
        self.loop.run_forever()
        logger.debug("ProxyLoop event loop stopped")

    def is_alive(self) -> bool:
        alive = self._thread.is_alive() and not self.loop.is_closed()
        if not alive:
            logger.warning("ProxyLoop not alive (thread=%s, loop_closed=%s)",
                           self._thread.is_alive(), self.loop.is_closed())
        return alive

    def stop(self) -> None:
        logger.info("ProxyLoop stopping...")

        async def _cancel_all() -> None:
            tasks = [t for t in asyncio.all_tasks(self.loop)
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
        try:
            fut = asyncio.run_coroutine_threadsafe(_cancel_all(), self.loop)
            fut.result(timeout=10)
        except TimeoutError:
            logger.warning("Cancelling tasks timed out")
        except Exception as e:
            logger.warning("Cancelling tasks, error: %s", e)

        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            logger.warning("ProxyLoop thread did not exit within 5s")
        else:
            logger.debug("ProxyLoop thread joined")
        if not self.loop.is_closed():
            self.loop.close()
            logger.debug("ProxyLoop event loop closed")
        logger.info("ProxyLoop stopped")

class BrowserController:
    def __init__(self, config: Init) -> None:
        self.config = config
        self.sessions: dict[str, SessionData] = {}
        self.browser_lock: asyncio.Lock = asyncio.Lock()
        self.main_driver: webdriver.Chrome
        self.fp_proxy: Optional[SidecarManager] = None

    @classmethod
    async def initialize(cls, config: Init) -> BrowserController:
        instance = cls(config)
        await instance.initialize_main_driver()
        await instance.initialize_proxy()
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
                self.fp_proxy = sidecar
                logger.info(sidecar)
        except Exception as e:
            logger.warning(e)

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
        _options.add_argument("--disable-features=UserAgentClientHint")
        _options.update_pref("download.prompt_for_download", False)
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

    async def get_session_browser(self, session: str) -> weakref.ProxyType[DrivenBrowser]:
        async with self.browser_lock:
            await self.check_main_driver()

            if session in self.sessions:
                logger.debug("Returning session %s", session)
                if self.sessions[session]['DrivenBrowser'].current_id < 0:
                    await self.remove_session(session)
                    raise RuntimeError("Browser is shutting down.")
                return weakref.proxy(self.sessions[session]['DrivenBrowser'])

            logger.debug("New session %s", session)

            drivenbrowser: DrivenBrowser = DrivenBrowser(weakref.ref(self), self.config, session,
                                                            weakref.ref(self.fp_proxy) if self.fp_proxy else None)
            await drivenbrowser.initialize_socks5()
            weakref.finalize(drivenbrowser, lambda: logger.debug("Garbage collected driver"))

            drivenbrowser_ref: weakref.ProxyType[DrivenBrowser] = weakref.proxy(drivenbrowser)

            timeout: int = self.config.driver_timeout
            task: asyncio.Task[None] = asyncio.create_task(self.browser_auto_destruction(drivenbrowser_ref, timeout))
            task.add_done_callback(partial(self.stale_check_callback, session=session))

            self.sessions[session] = {
                'StaleCheck': task,
                'DrivenBrowser': drivenbrowser}
            del drivenbrowser, task

            return drivenbrowser_ref

    async def get_temp_browser(self, session: str) -> tuple[DrivenBrowser, weakref.ProxyType[DrivenBrowser]]:
        await self.check_main_driver()
        logger.debug("Temp session")
        drivenbrowser: DrivenBrowser = DrivenBrowser(weakref.ref(self), self.config, session,
                                                        weakref.ref(self.fp_proxy) if self.fp_proxy else None)
        await drivenbrowser.initialize_socks5()
        return drivenbrowser, weakref.proxy(drivenbrowser)

    async def browser_auto_destruction(self, browser: weakref.ProxyType[DrivenBrowser], timeout: int) -> None:
        while True:
            await asyncio.sleep(5)

            logger.debug(
                "Checking %s - %s",
                str(browser.current_id),
                str(browser.in_use),
            )

            current_time = time.time()
            b_timeout = current_time - browser.last_used > timeout

            if not browser.in_use and b_timeout:
                break

        return
        # return {k: v for k, v in self.__dict__.items() if not callable(v) and not k.startswith('__')}

    def stale_check_callback(self, task: asyncio.Task[None], session: str) -> None:
        try:
            result = task.result()
            logger.debug("AutoDet completed: %s", str(result))
        except asyncio.CancelledError:
            logger.debug("AutoDet cancelled")
        except Exception:
            logger.warning("AutoDet failed: %s", traceback.format_exc())

        removal_task = asyncio.get_running_loop().create_task(
            self.remove_session(session),
            name="remove_session"
        )
        removal_task.add_done_callback(lambda t: logger.debug("remove_session %s completed", session))

    async def remove_session(self, session: str) -> None:
        try:
            self.sessions[session]['StaleCheck'].cancel()
            await self.sessions[session]['StaleCheck']
        except asyncio.CancelledError:
            logger.debug("Cancelled %s", session)
        except Exception as e:
            logger.debug(e)

        try:
            await asyncio.wait_for(self.sessions[session]['DrivenBrowser'].terminate_session(), timeout=60.0)
        except Exception as e:
            logger.error("terminate_session timed out for %s with: %s", session, traceback.format_exc())

        # I gave up, AI generated frame cleanup
        if sys.getrefcount(self.sessions[session]['DrivenBrowser']) > 2:
            for t in asyncio.all_tasks():
                if not t.done():
                    logger.debug("pending task %r: %s", t.get_name(), t.get_stack(limit=8))
            cleared = await _clear_frames(self.sessions[session]['DrivenBrowser'], module_filter="driverless.py")
            logger.debug(cleared)
        del self.sessions[session]['StaleCheck'] # type: ignore
        del self.sessions[session]['DrivenBrowser'] # type: ignore
        del self.sessions[session]

        logger.debug("Destroyed %s", session)

        return None

    async def shutdown_sessions(self) -> None:
        tasks: list[asyncio.Task[None]] = [asyncio.create_task(self._shutdown_session(key))
             for key in list(self.sessions.keys())]
        await asyncio.gather(*tasks)

        if self.fp_proxy:
            await self.fp_proxy.stop()
        await self.destroy_main_driver()

    async def _shutdown_session(self, session: str) -> None:
        logger.debug("Force %s", session)
        try:
            self.sessions[session]['StaleCheck'].cancel()
            logger.debug("Stopped driver for: %s", session)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("Unable to shutdown", exc_info=e)

class DrivenBrowser:
    def __init__(self, controller: weakref.ReferenceType[BrowserController],
                config: Init,
                session: str,
                fp_proxy: Optional[weakref.ReferenceType[SidecarManager]]):
        self.controller = controller
        self.session = session
        self.sessiontabs: dict[int, Target] = {}
        self.context: Optional[Context] = None
        self.current_id: int = random.randint(0, 100)
        self.last_used: float = time.time()
        self.in_use: int = 0
        self.downloads_dir: str = tempfile.mkdtemp(prefix=f"downloads_{session}_")
        logger.debug("Created dir %s", self.downloads_dir)

        self.config = config
        self.virt_disp: bool = config.virt_disp
        self.proxy_instance_port: int = 0
        self.fp_proxy = fp_proxy
        self.socks_proxy_instance: SessionProxy
        self.socks_proxy_loop: Optional[asyncio.AbstractEventLoop]

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

    async def start_browser(self) -> Context:
        controller = self.controller()
        if controller is None:
            raise Exception

        proxy: str = f"http://127.0.0.1:{self.proxy_instance_port}"
        try:
            context = await controller.main_driver.new_context(proxy_server=proxy)
            # Image testing selenium proxy https://archiveofourown.org/works/61648471?view_full_work=true&view_adult=true
            await context.set_download_behaviour('allowAndName', self.downloads_dir)
        except Exception as e:
            logger.warning("Error in creating context %s", str(e))
            await controller.check_main_driver()
            return await self.start_browser()

        logger.info("Started proxied context %s", proxy)
        return context

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
        return tab, self.current_id

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

    def intercept_urls(self, urls: list[str]):
        return self.socks_proxy_instance.intercept(urls)

    async def rotate_socks_proxy(self) -> bool:
        """
        Rotate the SOCKS5 proxy for this session.
        Returns True if successful, False otherwise.
        """
        try:
            new_proxy = self.socks_proxy_instance.rotate_proxy()
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
            new_proxy = self.socks_proxy_instance.set_proxy(proxy_url)
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
        """Get the current SOCKS5 proxy for this session"""

        return self.socks_proxy_instance.get_proxy()

    async def set_intercept_rule(self, urls: set[str], headers: list[tuple[str, str]]) -> None:
        self.socks_proxy_instance.set_header_rule(urls, headers)
        logger.info("Set intercept rule for session %s", self.session)

    async def remove_intercept_rule(self) -> None:
        self.socks_proxy_instance.clear_header_rule()
        logger.info("Removed intercept rule for session %s", self.session)

    async def destroy_tab(self, requestid: int) -> None:
        try:
            if requestid in self.sessiontabs:
                tab = self.sessiontabs.pop(requestid)
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
                        if self.context:
                            await self.context.execute_cdp_cmd("Target.closeTarget", {"targetId": target_id}, timeout=5)
                    except Exception as e:
                        logger.warning(e)
            else:
                logger.debug("Requestid not found. Chrome was destroyed?")
        except Exception as e:
            logger.warning("Unable to close the tab", exc_info=e)

    async def initialize_socks5(self) -> None:
        self.socks_proxy_instance = SessionProxy(
            host=self.config.host,
            port=0,  # OS-assigned, as before
            socks_pool=SocksProxyPool(self.config.socks5_file),
            ca_cert=self.config.mitm_ca_cert,
            ca_key=self.config.mitm_ca_key,
            config=ProxyConfig(connect_timeout=61.0, verify_ssl=self.config.verify_ssl),
            sidecar=self.fp_proxy() if self.fp_proxy else None,
        )

        # Get the shared loop instead of creating a new thread
        proxy_loop = ProxyLoop.get()
        self.socks_proxy_loop = proxy_loop.loop

        # Start the proxy on the shared loop (cross-thread call)
        future = asyncio.run_coroutine_threadsafe(
            self.socks_proxy_instance.start(),
            self.socks_proxy_loop,
        )

        # Wait for port assignment (blocks the calling coroutine, not the loop)
        self.proxy_instance_port = await asyncio.wrap_future(future)

        logger.info(
            "SOCKS5 proxy started on port %d (shared loop)",
            self.proxy_instance_port,
        )

    async def socks5_shutdown(self) -> None:
        """Stop the proxy server"""
        if not hasattr(self, "socks_proxy_instance") or not self.socks_proxy_instance:
            return
        loop = self.socks_proxy_loop
        if loop is None or loop.is_closed():
            return

        logger.info("Stopping SOCKS5 proxy...")

        # Stop the server
        future = asyncio.run_coroutine_threadsafe(
            self.socks_proxy_instance.stop(), loop
        )
        try:
            await asyncio.wait_for(asyncio.wrap_future(future), timeout=10.0)
        except asyncio.TimeoutError as e:
            logger.warning("SOCKS5 stop() timed out; cancelling")
            future.cancel()
        except Exception as e:
            logger.warning("stop error: %s", e)

        logger.info("SOCKS5 proxy stopped")

    async def broken_browser(self, current_id: int) -> None:
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
        loop = self.socks_proxy_loop
        if loop is None or loop.is_closed():
            return
        future = asyncio.run_coroutine_threadsafe(
            self.socks_proxy_instance.close_all_handlers(), loop
        )
        # Block in an executor so we don't stall our own event loop
        await asyncio.get_running_loop().run_in_executor(
            None, future.result, timeout
        )

    async def terminate_session(self) -> None:
        self.current_id = -1
        await self.destroy_driver(-1)
        del self.context
        await self.socks5_shutdown()
        del self.config
        logger.info("Terminated session: %s", self.session)
        return None

class ClientRequest:
    def __init__(self, stats: Stats, drivenbrowser: weakref.ProxyType[DrivenBrowser], requestid: int) -> None:
        self.stats: Stats = stats
        self.drivenbrowser: weakref.ProxyType[DrivenBrowser] = drivenbrowser
        self.timeout: float = 60.0
        self.img_workaround: bool = False
        self.requestid: int = requestid
        self.links: list[str] = []

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
                logging.error(e)

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
        await tab.execute_cdp_cmd("Network.clearBrowserCache")

        if "Content-Type" in headers:
            logger.debug("Raw params will be inserted.")
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

    async def correct_image_content(self, url: str, status_code: int, content_type: str, source: bytes) -> str:
        def check(pattern: bytes):
            link = re.search(pattern, source, flags=re.DOTALL)
            if link:
                new_url: str = (link.group(1)).decode()
                logger.info(f"Changing '{url}' -> '{new_url}'")
                raise OutdatedUrlError(new_url)
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
                check(br'<meta name=\"twitter:image\" data-react-helmet=\"true\" content=\"(.+?)\"><link rel=\"alternate\" type=\"application/json\+oembed\"')
            if netloc == 'imgbox.com':
                check(br'<meta property=\"og:image\" content=\"(.+?)\"/>')
            if netloc == 'postimg.cc':
                check(br'<meta property=\"og:image\" content=\"(.+?)\">')
            if netloc == 'rule34.xxx':
                check(br'Resize image.+?<a href=\"(http.+?)\"')
            if netloc.startswith("furry34com"):
                raise RefererError("Removing referer")
            if 'pinterest.com' in netloc:
                check(br'<link as="image" fetchPriority="high" href="(.+?)" ')

        if not self.img_workaround:
            if not content_type.lower().startswith('image') and not status_code == 404:
                raise ImageError(content_type, (status_code, content_type, source, "Not an image"))
            # This is for https://static.wikia.nocookie.net/walkthrough/images/3/3c/Link_On_Mario_Bros_stage.png/revision/latest?cb=20100316231141
            # As including the referer causes the website to return 404
            if urllib.parse.urlsplit(url).netloc == "static.wikia.nocookie.net" and status_code == 404:
                raise RefererError("Removing referer")

        return content_type

    async def driverless_get(self, tab: Target, url: str, image: Literal["True", "False"], headers: dict[str, str]) -> tuple[int, str, bytes, str]:
        response_headers: list[tuple[str, str]] = []
        referer: Optional[str] = headers.get('Referer')
        old = url
        content_type = "None"
        status_code = -10
        source: bytes = b"Failed"
        # For the infinite redirection https://archiveofourown.org/works/38595468
        redirects = 0
        error = "None"
        req: Optional[asyncio.Future[dict[str,str]]] = None

        if self.img_workaround:
            # Sometimes there is a need to reload or wait for a page to load. Sometimes it triggers a download.
            # 'https://i.gifer.com/embedded/download/4oCW.gif'
            logger.debug("WORKAROUND URL: %s | Referer: %s", url, str(referer))
            pg: dict[str, str] = await tab.get(url, referrer=referer, wait_load=True, timeout=self.timeout)
            if file := pg.get('guid_file'):
                logger.debug("Request result: %s", pg)
                with open(file, "rb") as file_source:
                    source = file_source.read()
                # Previous missed request left a file that we have no record of.
                await self.drivenbrowser.clear_downloads()
                return 200, "image/file", source, "File"
            del pg

        while True:
            download_started = asyncio.Event()
            download_started_task = asyncio.create_task(self.drivenbrowser.listen_for_download(tab, download_started))

            self.links = self.condition_url(url, old)

            if image == "True":
                await self.drivenbrowser.set_intercept_rule(set(self.links),
                    [('Sec-Fetch-Dest', 'image'), ('Sec-Fetch-Mode', 'no-cors'), ('Sec-Fetch-Site', 'cross-site'),
                    ('Accept', 'image/avif,image/webp,image/apng,image/svg+xml,image/*;q=0.8'), ('Priority', 'u=5, i')])

            try:
                logger.info("URL: %s | Referer: %s", self.links[0], str(referer))
                await tab.execute_cdp_cmd("Network.clearBrowserCache")
                async with self.drivenbrowser.intercept_urls(self.links) as cap:
                    req = asyncio.ensure_future(tab.get(self.links[0], referrer=referer, wait_load=False, timeout=self.timeout))
                    async for resp in cap:
                        status_code = resp.status_code
                        source = resp.body
                        content_type = resp.content_type.split(";", 1)[0]
                        response_headers = resp.headers
                        if redirects > 7:
                            status_code = 500
                            error = "Too Many Redirects"
                        break

                if download_started.is_set():
                    logger.debug("Download will begin")
                    params = await download_started_task
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
                    await self.drivenbrowser.remove_intercept_rule()

            logger.info("Page returned: '%s'", str(status_code))
            if status_code in [301, 302, 303, 307, 308] and response_headers:
                old = self.links[0]
                for header in response_headers:
                    if header[0].lower() == 'location':
                        url = header[1]
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

            break

        if image == "True":
            content_type = await self.correct_image_content(url, status_code, content_type, source)

        logger.info("Page returned: '%s'", content_type)

        return status_code, content_type, source, error

    async def main(self, request: ServerRequest) -> ServerResponse:
        result: tuple[int, str, bytes, str] = (-1, "None", b"None", "Failed to get a page.")
        tab, drivenbrowser_id = await self.drivenbrowser.get_tab(self.requestid)

        if request["cookies"]:
            logger.debug("We got extra cookies")
            await asyncio.gather(*(tab.add_cookie(cookie) for cookie in request["cookies"]))

        for attempt in range(0, 5):
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
            except OutdatedUrlError as e:
                request["url"] = str(e)
                await tab.get("about:blank")
                continue
            except ConnectionClosedError:
                logger.warning("Chrome exception, recovery attempt.")
                await self.drivenbrowser.broken_browser(drivenbrowser_id)
                tab, drivenbrowser_id = await self.drivenbrowser.get_tab(self.requestid)
                continue

            if result[0] == 525:
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
        raw_cookies: list[ResponseCookie] = await tab.get_cookies()
        if raw_cookies:# and request["image"] == "False":
            out_cookies = json.dumps(raw_cookies)

        return {"code": result[0], "content_type": result[1], "cookies": out_cookies, "source": base64.b64encode(result[2]).decode(), "errors": result[3]}

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
