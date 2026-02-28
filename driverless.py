from __future__ import annotations
import uvloop
uvloop.install()
import patch_func
from utls_bridge.sidecar import SidecarManager
from proxy_server import SessionProxy, SocksProxyPool, ProxyConfig

from typing import Optional, Literal, Any, TypedDict, TextIO, cast
import asyncio, zlib, argparse, configparser, sys, signal, logging
import ssl, base64, hashlib, json, re, threading
import weakref, gc, types, inspect
from xvfbwrapper import Xvfb
from asyncio.sslproto import SSLProtocol
from asyncio import StreamReader, StreamWriter, StreamReaderProtocol
from functools import partial

from selenium_driverless import webdriver
from selenium_driverless.types.by import By
from selenium_driverless.types.target import Target
from selenium_driverless.types.context import Context
from selenium_driverless.types.options import Options
from selenium_driverless.types.webelement import NoSuchElementException, WebElement
from cdp_socket.exceptions import CDPError
from websockets.exceptions import ConnectionClosedError

# All of this shit just to get a plain png out of the websites
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

# used for the timestamp in session
import time

# used for encoding POST parameters and extracting base website from urls
import urllib.parse

# used for choosing the random proxy ip, choosing the display
import random

# only used for debbuging
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

class CustomLogger(logging.Logger):
    def trace(self, message: object, *args: Any, stacklevel: int = 1, **kwargs: Any) -> None:
        if self.isEnabledFor(5):
            self._log(5, message, args, **kwargs, stacklevel=stacklevel + 1)

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
            logger.setLevel(logging.DEBUG)
            ch.setLevel(logging.DEBUG)
            self.log_lvl = logging.DEBUG
        if args.trace:
            logger.setLevel(5)
            ch.setLevel(5)
            self.log_lvl = 5
        logger.setLevel(self.log_lvl)
        ch.setLevel(self.log_lvl)

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
        self.chormium: Optional[str] = (
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
        self.clientcert: str = (
            args.cacert
            if args.cacert is not None
            else self.config.get("server", "cacert")
        )
        logger.debug((self.clientcert, self.key, self.cert))

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
            if hasattr(args, 'impersonate') and args.impersonate
            else self.config.get("server", "impersonate", fallback='')
        )
        self.impersonate_port: int = (
            args.impersonate_port
            if hasattr(args, 'impersonate_port') and args.impersonate_port
            else self.config.getint("server", "impersonate_port", fallback=0)
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

        logger.debug(f"Awaiting tasts {tasks_to_await}")
        resuts = await asyncio.gather(*tasks_to_await, return_exceptions=True)
        logger.debug(resuts)

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

        def stop_loop_callback(future: asyncio.Future[None]) -> None:
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
            context.load_verify_locations(cafile=self.init.clientcert)

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
                if drivenbrowser := drivenbrowser_ref():
                    drivenbrowser.in_use += 1
                    del drivenbrowser
                else:
                    raise RuntimeError("Drivenbrowser does not exists")
                content = await client_task
            except Exception as e:
                logger.warning(traceback.format_exc())
                self.stats.add_failed(request["url"], str(e))
                content['errors'] = traceback.format_exc()
            finally:
                drivenbrowser = drivenbrowser_ref()
                if drivenbrowser == None:
                    raise BaseException("State")
                if request["session"] == "None":
                    await drivenbrowser.terminate_session()
                    del _drivenbrowser
                else:
                    drivenbrowser.last_used = time.time()
                    drivenbrowser.in_use -= 1
                    await drivenbrowser.destroy_tab(reqid)
                del drivenbrowser
                if client:
                    await BrowserController._clear_frames(client)
                    del client
                    logger.debug("Deleted the client %s", request["session"])

            if content["code"] == -1:
                logger.warning("Failed to fetch %s", request["url"])
                self.stats.add_failed(request["url"], content["errors"])

            await self._cancel_task(heartbeat)

            response = await self.encrypt(response=content)
            await self.send_response(writer, response)
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
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self.writer_close_task(writer))
                if heartbeat:
                    tg.create_task(self._cancel_task(heartbeat))
                if client_task:
                    tg.create_task(self._cancel_task(client_task))

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
        packet: bytes = b""
        while True:
            data: bytes = await reader.read(8192)
            packet += data
            if b"\0" in data:
                logger.debug('End of data received')
                break
            if not data:
                logger.debug("No data received, closing connection.")
                raise ConnectionResetError("No Data")

        return packet

    async def send_response(self, writer: StreamWriter, response: bytes) -> None:
        sent: int = 0
        total: int = len(response)
        while sent < total:
            chunk: bytes = response[sent : sent + 8192]
            writer.write(chunk)
            await writer.drain()
            sent += len(chunk)
            complete: float = (sent / total) * 100
            # print(f"Progress: {complete:.2f}%", end="\r")
        logger.debug("Sent %s bytes successfully.", total)

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
                    listen_port=self.config.impersonate_port,
                    auto_restart=False,
                    verify_ssl=self.config.verify_ssl
                )
                await sidecar.start()
                self.fp_proxy = sidecar
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
        _options: Options = webdriver.ChromeOptions()
        if self.config.chormium:
            _options.binary_location = self.config.chormium
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
        # if config.sock and config.sock_2:
        #     _options.add_argument(config.sock)
        #     _options.add_argument(config.sock_2)
        self.main_driver = await webdriver.Chrome(max_ws_size=2 ** 30, options=_options)
        await self.main_driver.set_window_rect(x=0, y=0, width=50, height=50)
        del _options

    async def destroy_main_driver(self) -> None:
        # try:
        #     await self.main_driver.close(timeout=3)
        #     logger.debug("Closed: %s", str(self.main_driver))
        # except Exception as e:
        #     logger.warning("Driver close returned an error: [%s]", str(e))
        try:
            await self.main_driver.quit()
            logger.debug("Stopped: %s", str(self.main_driver))
        except Exception as e:
            logger.warning("Driver quit returned an error: [%s]", str(e))

    async def get_session_browser(self, session: str) -> weakref.ReferenceType[DrivenBrowser]:
        async with self.browser_lock:
            try:
                logger.debug(await self.main_driver.title)
            except ConnectionClosedError:
                await self.destroy_main_driver()
                await self.initialize_main_driver()

            if session in self.sessions:
                logger.debug("Returning session %s", session)
                if self.sessions[session]['DrivenBrowser'].current_id < 0:
                    await self.remove_session(session)
                    raise RuntimeError("Browser is shutting down.")
                return weakref.ref(self.sessions[session]['DrivenBrowser'])

            logger.debug("New session %s", session)

            drivenbrowser: DrivenBrowser = DrivenBrowser(weakref.ref(self.main_driver), self.config, session, weakref.ref(self.fp_proxy) if self.fp_proxy else None)
            await drivenbrowser.initialize_socks5()
            weakref.finalize(drivenbrowser, lambda: logger.debug("Garbage collected driver"))

            drivenbrowser_ref: weakref.ReferenceType[DrivenBrowser] = weakref.ref(drivenbrowser)

            timeout: int = self.config.driver_timeout
            task: asyncio.Task[None] = asyncio.create_task(self.browser_auto_destruction(drivenbrowser_ref, timeout))
            task.add_done_callback(partial(self.stale_check_callback, session=session))

            self.sessions[session] = {
                'StaleCheck': task,
                'DrivenBrowser': drivenbrowser}
            del drivenbrowser, task

            return drivenbrowser_ref

    async def get_temp_browser(self, session: str) -> tuple[DrivenBrowser, weakref.ReferenceType[DrivenBrowser]]:
        try:
            logger.debug(await self.main_driver.title)
        except ConnectionClosedError:
            async with self.browser_lock:
                await self.destroy_main_driver()
                await self.initialize_main_driver()
        logger.debug("Temp session")
        drivenbrowser: DrivenBrowser = DrivenBrowser(weakref.ref(self.main_driver), self.config, session, weakref.ref(self.fp_proxy) if self.fp_proxy else None)
        await drivenbrowser.initialize_socks5()
        return drivenbrowser, weakref.ref(drivenbrowser)

    async def browser_auto_destruction(self, browser: weakref.ReferenceType[DrivenBrowser], timeout: int) -> None:
        while True:
            await asyncio.sleep(5)

            br = browser()
            if br is None:
                logger.warning("Browser have been garbage collected.")
                break

            logger.debug(
                "Checking %s - %s",
                str(br.current_id),
                str(br.in_use),
            )

            current_time = time.time()
            b_timeout = current_time - br.last_used > timeout

            if not br.in_use and b_timeout:
                break

        del br
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
        try:
            _ = self.sessions[session]['StaleCheck'].result()
        except Exception as e:
            logger.debug(e)
        except asyncio.CancelledError:
            logger.debug("CancelledError")

        try:
            await self.sessions[session]['DrivenBrowser'].terminate_session()
        except Exception as e:
            logger.warning("Failed to execute terminate_session %s", str(e))

        # I gave up, AI generated frame cleanup
        if sys.getrefcount(self.sessions[session]['DrivenBrowser']) > 2:
            cleared = await self._clear_frames(self.sessions[session]['DrivenBrowser'], module_filter="driverless.py")
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

    @staticmethod
    async def _clear_frames(obj: Any, module_filter: str | None = None) -> int:
        if not __debug__:
            return 0
        """
        Forcefully destroy orphaned frames holding references to obj.
        This directly manipulates frame internals.
        """
        obj_id = id(obj)
        destroyed = 0
        def print_refs(obj, n: int):
            if n > 32:
                return
            print('  ' *(n - 2), f"--- Diagnosing refs to {type(obj).__name__} id={id(obj)} ---")
            for ref in gc.get_referrers(obj):
                if isinstance(ref, types.FrameType):
                    holding = [n for n, v in ref.f_locals.items() if id(v) == obj_id]
                    print('  ' *n, f"FRAME: {ref.f_code.co_filename}:{ref.f_lineno} "
                        f"func={ref.f_code.co_name} vars={holding}")
                    print_refs(ref, n+2)
                elif isinstance(ref, types.CoroutineType):
                    # DIRECT COROUTINE REFERENCE
                    coro_state = inspect.getcoroutinestate(ref)
                    state_names = {
                        inspect.CORO_CREATED: "CREATED",
                        inspect.CORO_RUNNING: "RUNNING",
                        inspect.CORO_SUSPENDED: "SUSPENDED", 
                        inspect.CORO_CLOSED: "CLOSED"
                    }
                    print('  ' *n, f"COROUTINE: {ref.cr_code.co_qualname} "
                        f"state={state_names.get(coro_state, 'UNKNOWN')} "
                        f"line={ref.cr_frame.f_lineno if ref.cr_frame else 'N/A'}")
                    if ref.cr_await is not None:
                        print('  ' *(n+1), f"⏳ AWAITING: {type(ref.cr_await).__name__}")
                elif isinstance(ref, dict):
                    keys = [k for k, v in ref.items() if id(v) == obj_id]
                    print('  ' *n, f"DICT: keys={keys}")
                elif isinstance(ref, list):
                    print('  ' *n, f"LIST: {type(ref).__name__}")
                else:
                    print('  ' *n, f"OTHER: {type(ref).__name__}")
                    print_refs(ref, n+2)
        print_refs(obj, 2)
        print("--- End diagnostic ---")
        # Active frames to skip
        active_frames: set[types.FrameType] = set()
        for task in asyncio.all_tasks():
            coro = getattr(task, "_coro", None)
            while coro:
                frame = getattr(coro, "cr_frame", None)
                if frame is not None:
                    active_frames.add(frame)
                coro = getattr(coro, "cr_await", None)
        # Only iterate objects that reference our target
        for frame_obj in gc.get_referrers(obj):
            if not isinstance(frame_obj, types.FrameType):
                continue

            if module_filter and module_filter not in frame_obj.f_code.co_filename:
                continue
            if frame_obj in active_frames:
                continue
            try:
                for var_name, var_value in frame_obj.f_locals.items():
                    if id(var_value) == obj_id:
                        logger.debug("Clearing frame %s:%s var=%s",
                                frame_obj.f_code.co_name, frame_obj.f_lineno, var_name)
                        frame_obj.f_locals[var_name] = None
                        destroyed += 1
                        break
            except Exception as e:
                logger.debug("Error nuking frame: %s", str(e))
        return destroyed

class DrivenBrowser:
    def __init__(self, chrome: weakref.ReferenceType[webdriver.Chrome],
                config: Init,
                session: str,
                fp_proxy: Optional[weakref.ReferenceType[SidecarManager]]):
        self.chrome = chrome
        self.session = session
        self.sessiontabs: dict[int, Target] = {}
        # If the MitM is on, it is slowing the ao3.
        self.context: Optional[Context] = None
        self.current_id: int = random.randint(0, 100)
        self.last_used: float = time.time()
        self.in_use: int = 0
        self.downloads_dir: str = f"/tmp/downloads_{str(random.randint(0, 100000))}"

        self.config = config
        self.virt_disp: bool = config.virt_disp
        self.proxy_instance_port: int = 0
        self.socks_proxy_instance: SessionProxy
        self.fp_proxy = fp_proxy

    async def get_browser(self) -> Context:
        if self.context is not None:
            return self.context

        logger.info("Starting new browser for %s", self.session)

        chrome = self.chrome()
        if chrome is None:
            raise RuntimeError("Chrome deleted")

        self.context = await self.start_browser(chrome)
        del chrome
        if not self.context:
            raise RuntimeError("No context")

        # Image testing selenium proxy https://archiveofourown.org/works/61648471?view_full_work=true&view_adult=true
        if not os.path.isdir(self.downloads_dir):
            os.mkdir(self.downloads_dir)
            logger.debug("Created dir %s", self.downloads_dir)
        await self.context.set_download_behaviour('allowAndName', self.downloads_dir)

        if self.virt_disp:
            await self.context.set_window_rect(x=0,y=0,width=1920,height=1080)

        logger.debug("Handed browser for %d", self.current_id)
        return self.context

    async def start_browser(self, chrome: webdriver.Chrome) -> Context:
        # if type_browser:
        proxy: str = f"http://127.0.0.1:{self.proxy_instance_port}"
        context = await chrome.new_context(proxy_server=proxy)
        logger.info("Started proxied context %s", proxy)
        return context

    async def get_tab(self, requestid: int) -> tuple[Target, int]:
        if requestid in self.sessiontabs:
            return self.sessiontabs[requestid], self.current_id
        if self.current_id < 0:
            raise RuntimeError("Shutdown?")

        try:
            browser_context = await self.get_browser()
            tab: Target = await browser_context.new_window(type_hint="tab", url="about:blank", activate=False)
            del browser_context
        except (ConnectionClosedError, TimeoutError):
            await self.broken_browser(self.current_id)
            return await self.get_tab(requestid)

        self.sessiontabs[requestid] = tab
        return (tab, self.current_id)

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

    async def get_current_socks_proxy(self) -> Optional[str]:
        """Get the current SOCKS5 proxy for this session"""

        return self.socks_proxy_instance.get_proxy()

    async def set_intercept_rule(self, urls: set[str], headers: list[tuple[str, str]]) -> None:
        self.socks_proxy_instance.set_rule(urls, headers)
        logger.info("Set intercept rule for session %s", self.session)

    async def remove_intercept_rule(self) -> None:
        self.socks_proxy_instance.clear_rule()
        logger.info("Removed intercept rule for session %s", self.session)

    async def destroy_tab(self, requestid: int) -> None:
        try:
            if requestid in self.sessiontabs:
                tab = self.sessiontabs.pop(requestid)
                socket = tab.socket
                trgt_id = tab.id

                try:
                    await tab.execute_cdp_cmd("Page.close", {}, timeout=5)
                except Exception as e:
                    logger.debug(e)
                    try:
                        await tab.execute_cdp_cmd("Target.closeTarget", {"targetId": trgt_id}, timeout=5)
                    except Exception as e:
                        logger.warning(e)
                    try:
                        await self.context.execute_cdp_cmd("Target.closeTarget", {"targetId": trgt_id}, timeout=5)
                    except Exception as e:
                        logger.warning(e)

                await socket.close()

                # Break reference cycles inside cdp_socket
                socket._responses.clear()
                socket._events.clear()
                socket._iter_callbacks.clear()
                if socket._task and socket._task.done():
                    socket._task = None
            else:
                logger.debug("Requestid not found. Chrome was destroyed?")
        except Exception as e:
            logger.warning("Unable to close the tab", exc_info=e)

    async def initialize_socks5(self) -> None:
        self.socks_proxy_instance = SessionProxy(
            host=self.config.host,
            port=self.proxy_instance_port,
            socks_pool=SocksProxyPool(self.config.socks5_file),
            ca_cert=self.config.mitm_ca_cert,
            ca_key=self.config.mitm_ca_key,
            config=ProxyConfig(connect_timeout=61.0, verify_ssl=self.config.verify_ssl),
            sidecar = self.fp_proxy() if self.fp_proxy else None,
            log_level=self.config.log_lvl
        )

        self._proxy_started = threading.Event()
        # Shared dict so the static method can pass data back
        _proxy_state: dict[str, Any] = {}

        self.socks_proxy_thread = threading.Thread(
            target=DrivenBrowser._run_socks5_proxy_static,
            args=(self.socks_proxy_instance, self._proxy_started, _proxy_state),
            daemon=True,
            name="SocksProxyThread",
        )
        self.socks_proxy_thread.start()

        if not self._proxy_started.wait(timeout=10):
            raise RuntimeError("SOCKS5 proxy failed to start within 10 seconds")

        self.proxy_instance_port = _proxy_state['port']
        self.socks_proxy_loop = _proxy_state['loop']
        del _proxy_state
        logger.info(
            "SOCKS5 proxy started on port %d (thread: %s)",
            self.proxy_instance_port,
            self.socks_proxy_thread.name,
        )

    @staticmethod
    def _run_socks5_proxy_static(proxy_instance: 'SessionProxy', started_event: threading.Event, state: dict[str, Any]) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        state['loop'] = loop

        try:
            port = loop.run_until_complete(proxy_instance.start())
            state['port'] = port
            started_event.set()
            loop.run_forever()
        except asyncio.CancelledError:
            logger.info("SOCKS5 proxy loop cancelled")
        except Exception:
            logger.error("SOCKS5 proxy thread error: %s", traceback.format_exc())
            started_event.set()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                try:
                    results = loop.run_until_complete(
                        asyncio.wait_for(
                            asyncio.gather(*pending, return_exceptions=True),
                            timeout=4.0
                        )
                    )
                    for task, result in zip(pending, results):
                        if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                            logger.debug("Task %s raised during cancel: %s", task.get_name(), result)
                except asyncio.TimeoutError:
                    still_pending = [t for t in pending if not t.done()]
                    for t in still_pending:
                        logger.warning("Task did not finish cancellation: %s coro=%s",
                                    t.get_name(), t.get_coro())
            loop.close()

    async def socks5_shutdown(self) -> None:
        """Stop the proxy server and its thread."""
        if not hasattr(self, "socks_proxy_instance") or not self.socks_proxy_instance:
            return
        if not hasattr(self, "socks_proxy_loop") or self.socks_proxy_loop.is_closed():
            return

        logger.info("Stopping SOCKS5 proxy...")
        loop = self.socks_proxy_loop
        future = asyncio.run_coroutine_threadsafe(
            self.socks_proxy_instance.close_all_handlers(), loop
        )

        logger.trace("Awaiting close_all_handlers")
        try:
            await asyncio.wait_for(asyncio.wrap_future(future), timeout=10.0)
        except (Exception, asyncio.TimeoutError) as e:
            logger.warning("close_all_handlers error: %s", e)

        future = asyncio.run_coroutine_threadsafe(
            self.socks_proxy_instance.stop(), loop
        )
        logger.trace("Awaiting stop")
        try:
            await asyncio.wrap_future(future)
        except Exception as e:
            logger.warning("stop error: %s", e)

        loop.call_soon_threadsafe(loop.stop)
        if self.socks_proxy_thread and self.socks_proxy_thread.is_alive():
            await asyncio.get_running_loop().run_in_executor(
                None, self.socks_proxy_thread.join, 5
            )
            if self.socks_proxy_thread.is_alive():
                logger.warning("SOCKS5 proxy thread did not exit cleanly")

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
            logger.warning("Unable to clear downloads: [%s]", exc_info=e)

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
        logger.debug("Terminated session: %s", self.session)
        return None

class ClientRequest:
    def __init__(self, stats: Stats, drivenbrowser: weakref.ReferenceType[DrivenBrowser], requestid: int) -> None:
        self.stats: Stats = stats
        self.drivenbrowser: weakref.ReferenceType[DrivenBrowser] = drivenbrowser
        self.timeout: float = 60.0
        self.img_workaround: bool = False
        self.requestid: int = requestid
        self.links: list[str] = []
        self.request_queue: asyncio.Queue[ChromeResponse]

    async def cloudflare_captcha_checked(self, tab: Target, session: str) -> bool:
        try:
            container: WebElement = await tab.find_element(
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
                logger.warning("Failed to locate the emenets: [%s]", str(e))
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
            except NoSuchElementException as e:
                logger.debug("Captcha is gone?")
            except Exception as e:
                logger.debug(e)
            finally:
                await asyncio.sleep(random.randint(1, 3))
                await tab.refresh()
                await self.page_loaded(tab)

            try:
                container = await tab.find_element(
                    By.XPATH,
                    """//input[@type='hidden' and starts-with(@id, 'cf-chl-widget-') and substring(@id, string-length(@id) - string-length('_response') + 1) = '_response']/..""",
                    timeout=1,
                )
            except NoSuchElementException as e:
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
        await tab.pointer.click(x_or_elem=int(iframe_rect["x"]),y=int(iframe_rect["y"]))
        try:
            tries: int = 0
            while await tab.find_element(By.XPATH, '//span[@class="Text Text_weight_medium Text_typography_headline-s"]', timeout=3) is not None and tries < 6:
                logger.debug(await tab.find_element(By.XPATH, '//span[@class="Text Text_weight_medium Text_typography_headline-s"]'))
                await asyncio.sleep(1)
                tries += 1
        except NoSuchElementException:
            return True
        return False

    async def is_captcha(self, tab: Target, code: int, session: str) -> bool:
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
            if await self.cloudflare_captcha_checked(tab, session):
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
        raw_response: str = 'None'
        # AO3 does not respond with the elements that indicate that user has logged in.
        await tab.execute_cdp_cmd("Network.clearBrowserCache")

        if "Content-Type" not in headers:
            headers['Content-Type'] = "application/x-www-form-urlencoded"
            params_dict: dict[str, str] = json.loads(params)
            encoded_params: str = urllib.parse.urlencode(params_dict)
        else:
            logger.debug("Raw params will be inserted.")
            encoded_params = params
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

        if int(response["statusCode"]) < 200 or int(response["statusCode"]) > 300:
            logger.debug('PostExcp')

        logger.info("POST returned: '%s'", str(status_code))
        logger.info("POST returned: '%s'", response["responseURL"])
        logger.info("POST type: '%s'", content_type)

        return (status_code, content_type, source, "None")

    def condition_url(self, url: str, old: str) -> list[str]:
        split_url = urllib.parse.urlparse(url)
        split_old = urllib.parse.urlsplit(old)
        netloc = split_url.netloc or split_old.netloc

        https_parts = split_url._replace(scheme="https", netloc=netloc)
        https_url = urllib.parse.urlunparse(https_parts)
        http_parts = split_url._replace(scheme="http", netloc=netloc)
        http_url = urllib.parse.urlunparse(http_parts)

        https_parts = split_url._replace(scheme="https", netloc=netloc, fragment="")
        https_url_part = urllib.parse.urlunparse(https_parts)
        http_parts = split_url._replace(scheme="http", netloc=netloc, fragment="")
        http_url_part = urllib.parse.urlunparse(http_parts)

        logger.debug((https_url, http_url))
        return [https_url, http_url, https_url_part, http_url_part]

    async def correct_image_content(self, url: str, status_code: int, content_type: str, source: bytes) -> str:
        def check(pattern: bytes):
            link = re.search(pattern, source)
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
            if urllib.parse.urlsplit(url).netloc == 'imgur.com':
                check(br'<meta name=\"twitter:image\" data-react-helmet=\"true\" content=\"(.+?)\"><link rel=\"alternate\" type=\"application/json\+oembed\"')
            if urllib.parse.urlsplit(url).netloc == 'imgbox.com':
                check(br'<meta property=\"og:image\" content=\"(.+?)\"/>')
            if urllib.parse.urlsplit(url).netloc == 'postimg.cc':
                check(br'<meta property=\"og:image\" content=\"(.+?)\">')
            if urllib.parse.urlsplit(url).netloc.startswith("furry34com"):
                raise RefererError("Removing referer")
            if 'pinterest.com' in urllib.parse.urlsplit(url).netloc:
                check(br'<link as="image" fetchPriority="high" href="(.+?)" ')

        if not self.img_workaround:
            if not content_type.lower().startswith('image'):
                raise ImageError(content_type, (status_code, content_type, source, "Not an image"))
            # This is for https://static.wikia.nocookie.net/walkthrough/images/3/3c/Link_On_Mario_Bros_stage.png/revision/latest?cb=20100316231141
            # As including the referer causes the website to return 404
            if status_code == 404:
                raise RefererError("Removing referer")

        return content_type

    async def driverless_get(self, tab: Target, url: str, image: Literal["True", "False"], headers: dict[str, str], session: str) -> tuple[int, str, bytes, str]:
        response_headers: Optional[list[tuple[str, str]]] = None
        referer: Optional[str] = headers.get('Referer')
        old: str = url
        content_type: Optional[str] = None
        status_code: int = -10
        source: bytes = b"Failed"
        # For the infinite redirection https://archiveofourown.org/works/38595468
        redirects = 0
        error = "None"

        if self.img_workaround:
            # Sometimes there is a need to reload or wait for a page to load. Sometimes it triggers a download.
            # 'https://i.gifer.com/embedded/download/4oCW.gif'
            logger.debug("WORKAROUND URL: %s | Referer: %s", url, str(referer))
            pg: dict[str, Any] = await tab.get(url, referrer=referer, wait_load=True, timeout=self.timeout)
            if file := pg.get('guid_file'):
                logger.debug("Reqeust result: %s", pg)
                with open(file, "rb") as file:
                    source = file.read()
                # Previous missed request left a file that we have no record of.
                await self.drivenbrowser().clear_downloads()
                return (200, "image/file", source, "File")
            del pg

        while True:
            self.links = self.condition_url(url, old)

            if image == "True":
                await self.drivenbrowser().set_intercept_rule(set(self.links),
                    [('Sec-Fetch-Dest', 'image'), ('Sec-Fetch-Mode', 'no-cors'), ('Sec-Fetch-Site', 'cross-site'),
                    ('Accept', 'image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5'), ('Priority', 'u=5, i')])

            req: Optional[asyncio.Task[dict[str, Any]]] = None
            try:
                logger.debug("URL: %s | Referer: %s", self.links[0], str(referer))
                await tab.execute_cdp_cmd("Network.clearBrowserCache")
                async with self.drivenbrowser().intercept_urls(self.links) as cap:
                    req = asyncio.create_task(tab.get(self.links[0], referrer=referer, wait_load=False, timeout=self.timeout))
                    async for resp in cap:
                        status_code = resp.status_code
                        source = resp.body
                        content_type = resp.content_type.split(";", 1)[0]
                        response_headers = resp.headers
                        if redirects > 7:
                            status_code = 500
                            error = "Too Many Redirects"
                        break

                if not (400 <= status_code < 500):
                    await tab.get("about:blank", timeout=self.timeout)
                result = await req
                logger.debug("Reqeust result: %s", str(result))
            except CDPError as e:
                if not (e.code == -32602 and e.message == 'Invalid InterceptionId.'):
                    raise e
            except BaseException as e:
                e.__traceback__ = None
                raise e from None
            finally:
                if req is not None and not req.done():
                    req.cancel()
                if req is not None:
                    try:
                        await req
                    except (asyncio.CancelledError, Exception) as e:
                        e.__traceback__ = None
                req = None
                if image == "True":
                    await self.drivenbrowser().remove_intercept_rule()

            if status_code in [301, 302, 303, 307, 308] and response_headers:
                old = self.links[0]
                for header in response_headers:
                    if header[0] == 'location':
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
                return (status_code, "None", b"None", f"Could not get a full response ({headers})")

            logger.info("Page returned: '%s'", str(status_code))
            break

        if image == "True":
            content_type = await self.correct_image_content(url, status_code, content_type, source)

        logger.info("Page returned: '%s'", content_type)

        return (status_code, content_type, source, error)

    async def main(self, request: ServerRequest) -> ServerResponse:
        result: tuple[int, str, bytes, str] = (-1, "None", b"None", "Failed to get a page.")
        tab, drivenbrowser_id = await self.drivenbrowser().get_tab(self.requestid)

        if request["cookies"]:
            logger.debug("We got extra cookies")
            await asyncio.gather(*(tab.add_cookie(cookie) for cookie in request["cookies"]))

        for attempt in range(0, 5):
            logger.info("Attempt %s for %s", str(attempt), request['session'])
            try:
                if request["method"] == "GET":
                    result = await asyncio.wait_for(self.driverless_get(tab=tab, url=request["url"], headers=request["headers"], image=request["image"], session=request['session']),
                                                    timeout=self.timeout*1.2)
                elif request["method"] == "POST":
                    result = await asyncio.wait_for(self.driverless_post(tab=tab, path=request["url"], headers=request["headers"], params=request["parameters"]),
                                                    timeout=self.timeout*1.2)
                else:
                    logger.error("Not supported HTTP method: %s", request["method"])
                    return {"code": -1, "content_type": "None", "source": "RmFpbGVk", "cookies": "None", "errors": "Not supported HTTP method"}
            except TimeoutError:
                logger.warning("TimeoutError at content: %s", result[3])
                await self.drivenbrowser().destroy_tab(self.requestid)
                tab, drivenbrowser_id = await self.drivenbrowser().get_tab(self.requestid)
                continue
            except ImageError as e:
                logger.debug("Image Error: %s", str(e))
                self.img_workaround = True
                result = e.response
                await self.is_captcha(tab, result[0], request['session'])
                continue
            except RefererError:
                self.img_workaround = True
                request["headers"].pop('Referer', None)
                continue
            except OutdatedUrlError as e:
                request["url"] = str(e)
                continue
            except ConnectionClosedError:
                logger.warning("Chrome exception, recovery attempt.")
                await self.drivenbrowser().broken_browser(drivenbrowser_id)
                tab, drivenbrowser_id = await self.drivenbrowser().get_tab(self.requestid)
                continue

            if result[0] != 404 and 400 < result[0] < 500:
                page_title = await tab.title
                if 'used Cloudflare to restrict hotlinking' in page_title:
                    logger.debug(page_title)
                    request['headers']['Referer'] = request['url']
                    continue

                if await self.is_captcha(tab, result[0], request['session']):
                    continue
            break
        else:
            logger.warning("Failed to get the content. Sending as is!")

        await tab.get("about:blank", wait_load=True, timeout=self.timeout)

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

logging.setLoggerClass(CustomLogger)
logging.addLevelName(5, "TRACE")
# Set up logging
logger: CustomLogger = logging.getLogger(__name__)
# logger.propagate = False
# Create console handler
ch: logging.StreamHandler[TextIO] = logging.StreamHandler()
# Create formatter and add it to the handler
formatter: ColoredFormatter = ColoredFormatter('%(elapsed)s | %(levelname)-8s | %(filename)s | %(funcName)s[%(lineno)d] | %(message)s')
ch.setFormatter(formatter)
# Add the handler to the logger
logger.addHandler(ch)

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

parser.add_argument('--mitm-cert', dest='mitm_ca_key', type=str, metavar='PATH', help=argparse.SUPPRESS)
parser.add_argument('--mitm-key', dest='mitm_ca_cert', type=str, metavar='PATH', help=argparse.SUPPRESS)

parser.add_argument('--impersonate', dest='impersonate', type=str, default='', help=argparse.SUPPRESS)
parser.add_argument('--impersonate-port', dest='impersonate_port', type=int, metavar='PORT', help=argparse.SUPPRESS)

args: argparse.Namespace = parser.parse_args()

handler = (lambda e: logger.debug(f'Event-handler: {e.__class__.__name__}: {str(e)}'))
sys.modules["selenium_driverless"].EXC_HANDLER = handler # type: ignore
sys.modules["cdp_socket"].EXC_HANDLER = handler # type: ignore

if __name__ == "__main__":
    try:
        Init().prepserver()
    except Exception as e:
        logger.critical('Failed to initialize %s', str(traceback.format_exc()))
    finally:
        sys.exit(0)
