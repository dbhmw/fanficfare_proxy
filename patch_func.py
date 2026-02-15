
import asyncio
import typing
from cdp_socket.socket import SingleCDPSocket
from cdp_socket.exceptions import SocketExcitedError,CDPError
# 1. Patch exec to aggressively clean up futures
_orig_exec = SingleCDPSocket.exec
async def _patched_exec(self, method: str, params: dict | None = None, timeout: float = 2):
    _id = await self.send(method=method, params=params)
    self._responses[_id]
    fut = self._responses[_id]
    try:
        res = await asyncio.wait_for(fut, timeout=timeout)
        return res
    except asyncio.TimeoutError as e:
        e.__traceback__ = None  # Clear traceback
        if self._task.done():
            if self._exc:
                self._exc.__traceback__ = None
                raise self._exc from None
            elif self._task._exception:
                self._task._exception.__traceback__ = None
                raise self._task._exception from None
            else:
                raise SocketExcitedError("socket coroutine excited without exception") from None
        raise asyncio.TimeoutError(
            f'got no response for method: "{method}", params: {params}'
            f"\nwithin {timeout} seconds") from None
    finally:
        self._responses.pop(_id, None)
        if hasattr(fut, '_callbacks') and fut._callbacks is not None:
            fut._callbacks.clear()
        if fut.done() and not fut.cancelled():
            try:
                exc = fut.exception()
                if exc and hasattr(exc, '__traceback__'):
                    exc.__traceback__ = None
            except (asyncio.CancelledError, asyncio.InvalidStateError):
                pass
SingleCDPSocket.exec = _patched_exec


import websockets
# 2. Patch close to clear all internal state
_orig_close = SingleCDPSocket.close
async def _patched_close(self, code=1000, reason=''):
    if self._ws.state == websockets.protocol.State.OPEN:
        try:
            await self._ws.close(code=code, reason=reason)
        except AttributeError as e:
            if e.args[0] == "'NoneType' object has no attribute 'encode'":
                # closed
                pass
            else:
                raise e

    if self._exc is not None:
        if hasattr(self._exc, '__traceback__'):
            self._exc.__traceback__ = None
        self._exc = None

    if self._task is not None:
        if self._task.done() and not self._task.cancelled():
            try:
                exc = self._task.exception()
            except (asyncio.CancelledError, asyncio.InvalidStateError):
                exc = None
            if exc and hasattr(exc, '__traceback__'):
                exc.__traceback__ = None
        self._task = None

    for fut in self._responses.values():
        if hasattr(fut, '_callbacks') and fut._callbacks is not None:
            fut._callbacks.clear()
        if fut.done() and not fut.cancelled():
            try:
                exc = fut.exception()
            except (asyncio.CancelledError, asyncio.InvalidStateError):
                exc = None
            if exc and hasattr(exc, '__traceback__'):
                exc.__traceback__ = None
    self._responses.clear()

    self._events.clear()
    self._iter_callbacks.clear()
    self.on_closed.clear()
SingleCDPSocket.close = _patched_close


# 3. Patch _rec_coro to clear exception locals after setting them on futures
_orig_rec_coro = SingleCDPSocket._rec_coro
async def _patched_rec_coro(self):
    try:
        async for data in self._ws:
            try:
                data = await self.load_json(data)
            except Exception as e:
                from cdp_socket import EXC_HANDLER
                EXC_HANDLER(e)
                data = {"method": "DecodeError", "params": {"e": e}}
            err = data.get('error')
            _id = data.get("id")
            if err is None:
                if _id is None:
                    method = data.get("method")
                    params = data.get("params")
                    callbacks = self._events[method]
                    for callback in callbacks:
                        await self._handle_callback(callback, params)
                    for _id, fut_result_setter in list(self._iter_callbacks[method].items()):
                        try:
                            fut_result_setter(params)
                        except asyncio.InvalidStateError:
                            pass
                        try:
                            del self._iter_callbacks[method][_id]
                        except KeyError:
                            pass
                else:
                    try:
                        self._responses[_id].set_result(data["result"])
                    except asyncio.InvalidStateError:
                        try:
                            del self._responses[_id]
                        except KeyError:
                            pass
            else:
                exc = CDPError(error=err)
                try:
                    self._responses[_id].set_exception(exc)
                except asyncio.InvalidStateError:
                    try:
                        del self._responses[_id]
                    except KeyError:
                        pass
                # THIS IS THE KEY FIX: clear the traceback and drop the local
                exc.__traceback__ = None
                del exc
    except websockets.exceptions.ConnectionClosedError as e:
        if self.on_closed:
            self._exc = e
            for callback in self.on_closed:
                await self._handle_callback(callback, code=e.code, reason=e.reason)
SingleCDPSocket._rec_coro = _patched_rec_coro


from selenium_driverless.types.target import Target, TargetInfo
_orig_get = Target.get
async def _patched_get(self, url: str, referrer: str | None = None, wait_load: bool = True, timeout: float = 30):
    if url == "about:blank":
        wait_load = False
    result = {}

    if "#" in url:
        current_url_base = (await self.current_url).split("#")[0]
        if url[0] == "#":
            url = current_url_base + url
            wait_load = False
        elif url.split("#")[0] == current_url_base:
            wait_load = False

    wait = None
    get = None  # Initialize here
    
    try:
        if wait_load:
            if not self._page_enabled:
                await self.execute_cdp_cmd("Page.enable")

            from selenium_driverless.utils.utils import safe_wrap_fut
            wait = asyncio.ensure_future(asyncio.wait([
                safe_wrap_fut(self.wait_for_cdp("Page.loadEventFired", timeout=None)),
                safe_wrap_fut(self.wait_download(timeout=None))
            ], timeout=timeout, return_when=asyncio.FIRST_COMPLETED))

            await asyncio.sleep(0.01)

        args = {"url": url, "transitionType": "link"}
        if referrer:
            args["referrer"] = referrer
        get = asyncio.ensure_future(self.execute_cdp_cmd("Page.navigate", args, timeout=timeout))

        if wait_load and wait is not None:
            done, pending = await wait
            # Clean up all pending futures
            for pend in pending:
                pend.cancel()
                try:
                    await pend
                except (asyncio.CancelledError, Exception):
                    pass
            
            if not done:
                # Timeout - must retrieve exception from get future
                if not get.done():
                    get.cancel()
                try:
                    await get
                except (asyncio.CancelledError, Exception):
                    pass
                # Clear local refs before raising
                get = None
                wait = None
                raise asyncio.TimeoutError(f'page: "{url}" didn\'t load within timeout of {timeout}') from None
            result = done.pop().result()
        
        await get
        await self._on_loaded()
        return result
        
    except BaseException as e:
        e.__traceback__ = None
        
        # Clean up futures
        if get is not None and not get.done():
            get.cancel()
        if get is not None:
            try:
                await get
            except (asyncio.CancelledError, Exception) as cleanup_exc:
                cleanup_exc.__traceback__ = None
        
        if wait is not None and not wait.done():
            wait.cancel()
        if wait is not None:
            try:
                await wait
            except (asyncio.CancelledError, Exception) as cleanup_exc:
                cleanup_exc.__traceback__ = None
        
        # Delete local references BEFORE re-raising
        get = None
        wait = None
        raise e from None
    finally:
        # Extra safety: ensure locals are cleared
        get = None
        wait = None
Target.get = _patched_get


from selenium_driverless.types.context import Context
_orig_window_handles = Context.window_handles
@property
async def _patched_window_handles(self) -> list[TargetInfo]:
    """Returns the handles of all windows within the current session."""
    tabs = []
    targets = await self.targets
    for info in list(targets.values()):
        if info.type == "page":
            tabs.append(info)
    return tabs
setattr(Context, 'window_handles', _patched_window_handles)


from selenium_driverless.scripts.driver_utils import add_cookie
_orig_add_cookie = Target.add_cookie
async def _patched_add_cookie(self, cookie_dict) -> None:
    if not (cookie_dict.get("url") or cookie_dict.get("domain") or cookie_dict.get("path")):
        cookie_dict["url"] = await self.current_url
    context_id = None
    # noinspection PyProtectedMember
    if self._context._is_incognito:
        context_id = await self.browser_context_id
    return await add_cookie(target=self, cookie_dict=cookie_dict, context_id=context_id)
Target.add_cookie = _patched_add_cookie


from selenium_driverless.webdriver import Chrome
from selenium_driverless.types.options import Options as ChromeOptions
_orig_init = Chrome.__init__
def __init(self, options: ChromeOptions = None, timeout: float = 30, debug: bool = False, max_ws_size: int = 2 ** 27) -> None:
    _orig_init(self, options=options, timeout=timeout, debug=debug, max_ws_size=max_ws_size)
    self._is_developer_mode = False
Chrome.__init__ = __init


_orig_new_context = Chrome.new_context
async def _patched_new_context(self, proxy_bypass_list: typing.List[str] = None, proxy_server: str = True,
                          universal_access_origins: typing.List[str] = None, url: str = "about:blank") -> Context:
    await self.enable_developer_mode()
    return await _orig_new_context(self, proxy_bypass_list=proxy_bypass_list, proxy_server=proxy_server,universal_access_origins=universal_access_origins, url=url)
Chrome.new_context = _patched_new_context


from selenium_driverless import EXC_HANDLER
async def enable_developer_mode(self, timeout: float = 10):
    """enable developer mode"""
    if not self._is_developer_mode:
        self._is_developer_mode = True
        page = None
        try:
            base_ctx = self._base_context
            page: Context = await base_ctx.new_window("tab", "chrome://extensions", activate=False)
            script = """
                async function make_dev_global(){
                    await chrome.developerPrivate.updateProfileConfiguration({
                        inDeveloperMode: true
                    });
                };
                await make_dev_global()
            """
            await asyncio.sleep(0.1)
            await page.eval_async(script, timeout=timeout, unique_context=False)
        except Exception as e:
            EXC_HANDLER(e)
            self._is_developer_mode = False
            if page:
                await page.close()
            return await self.enable_developer_mode()
        self._is_developer_mode = True
        await page.close()
setattr(Chrome, 'enable_developer_mode', enable_developer_mode)