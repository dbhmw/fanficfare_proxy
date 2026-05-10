
import asyncio
import typing
import gc
import inspect
import sys
import types
import websockets
from typing import Any
from cdp_socket.socket import SingleCDPSocket
from cdp_socket.exceptions import SocketExcitedError,CDPError
from selenium_driverless.types.target import Target, TargetInfo
from selenium_driverless.types.context import Context
from selenium_driverless.scripts.driver_utils import add_cookie
from selenium_driverless.webdriver import Chrome
from selenium_driverless.types.options import Options as ChromeOptions
from selenium_driverless import EXC_HANDLER

# 1. Patch exec to aggressively clean up futures
_orig_exec = SingleCDPSocket.exec
async def _patched_exec(self, method, params=None, timeout=2):
    _id = await self.send(method=method, params=params)
    fut = self._responses[_id]
    try:
        return await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        if self._task.done():
            if self._exc:
                self._exc.__traceback__ = None
                raise type(self._exc)(*self._exc.args) from None
            if self._task._exception:
                src = self._task._exception
                src.__traceback__ = None
                raise type(src)(*src.args) from None
            raise SocketExcitedError("socket coroutine exited without exception") from None
        raise asyncio.TimeoutError(
            f'got no response for method: "{method}", params: {params}'
            f"\nwithin {timeout} seconds") from None
    except CDPError as e:
        e.__traceback__ = None
        raise CDPError(*e.args) from None
    finally:
        self._responses.pop(_id, None)
        fut = None
SingleCDPSocket.exec = _patched_exec


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
SingleCDPSocket.close = _patched_close


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


# Refs we describe but never recurse through — they're program structure or
# scheduler plumbing, not live state. Climbing past a Task into the loop's
# _ready deque, or past a function into its module, just produces noise.
_OPAQUE_BOUNDARIES = (
    types.ModuleType,
    types.FunctionType,
    types.BuiltinFunctionType,
    types.MethodType,
    types.MethodWrapperType,
    types.WrapperDescriptorType,
    types.MethodDescriptorType,
    types.GetSetDescriptorType,
    types.MemberDescriptorType,
    type,
    types.CodeType,
    asyncio.Task,
    asyncio.Future,
    asyncio.Handle,
    asyncio.TimerHandle,
)

# Pure noise from gc internals / asyncio scheduler innards.
_TRANSIENT_TYPE_NAMES = {
    "list_iterator", "tuple_iterator", "set_iterator",
    "dict_keyiterator", "dict_valueiterator", "dict_itemiterator",
    "dict_keys", "dict_values", "dict_items",
    "TaskStepMethWrapper",
    "_WeakSet",
}
async def _clear_frames(ob: Any, module_filter: str | None = None) -> int:
        """Diagnostic refgraph + frame-local clearer.

        Walks gc.get_referrers upward from `ob`, prints a tree of holders with
        full cycle and shared-node detection, then clears any frame locals
        that pin `ob` (skipping active coroutines).
        """
        if not __debug__:
            return 0

        obj_id = id(ob)
        destroyed = 0

        # ---------- diagnostic refgraph ----------
        seen: dict[int, str] = {}      # id(node) -> "#N", also our visited set
        cycles: int = 0
        truncated: list[str] = []
        MAX_NODES = 128
        MAX_DEPTH = 32
        MAX_REFS_PER_NODE = 16

        def label_for(o: Any) -> str:
            oid = id(o)
            if oid in seen:
                return seen[oid]
            s = f"#{len(seen) + 1}"
            seen[oid] = s
            return s

        def describe(ref: Any) -> str:
            if isinstance(ref, types.FrameType):
                fname = ref.f_code.co_filename.rsplit("/", 1)[-1]
                return f"FRAME {fname}:{ref.f_lineno} in {ref.f_code.co_name}()"
            if isinstance(ref, types.CoroutineType):
                state_name = {
                    inspect.CORO_CREATED: "CREATED",
                    inspect.CORO_RUNNING: "RUNNING",
                    inspect.CORO_SUSPENDED: "SUSPENDED",
                    inspect.CORO_CLOSED: "CLOSED",
                }.get(inspect.getcoroutinestate(ref), "?")
                line = ref.cr_frame.f_lineno if ref.cr_frame else "?"
                return (f"COROUTINE {ref.cr_code.co_qualname} "
                        f"state={state_name} at line {line}")
            if isinstance(ref, asyncio.Task):
                try:
                    name = ref.get_name()
                except Exception:
                    name = "?"
                return f"TASK name={name!r} done={ref.done()}"
            if isinstance(ref, asyncio.Future):
                return f"FUTURE done={ref.done()}"
            if isinstance(ref, types.MethodType):
                holder = type(ref.__self__).__qualname__
                return f"BOUND_METHOD {holder}.{ref.__func__.__name__}"
            if isinstance(ref, types.FunctionType):
                return f"FUNCTION {ref.__qualname__} (closure)"
            if isinstance(ref, types.CellType):
                return "CELL"
            if isinstance(ref, types.ModuleType):
                return f"MODULE {ref.__name__}"
            if isinstance(ref, type):
                return f"CLASS {ref.__qualname__}"
            if isinstance(ref, dict):
                return f"DICT len={len(ref)}"
            if isinstance(ref, (list, tuple, set, frozenset)):
                return f"{type(ref).__name__.upper()} len={len(ref)}"
            mod = type(ref).__module__
            qn = type(ref).__qualname__
            return qn if mod in ("builtins", "__main__") else f"{mod}.{qn}"

        def held_at(ref: Any, target_id: int) -> str:
            """Where inside `ref` does the target live?"""
            try:
                if isinstance(ref, types.FrameType):
                    names = [n for n, v in ref.f_locals.items()
                             if id(v) == target_id]
                    return f" vars={names}" if names else ""
                if isinstance(ref, types.CoroutineType) and ref.cr_frame is not None:
                    names = [n for n, v in ref.cr_frame.f_locals.items()
                             if id(v) == target_id]
                    return f" cr_locals={names}" if names else ""
                if isinstance(ref, dict):
                    keys: list[str] = []
                    for k, v in ref.items():
                        if id(v) == target_id:
                            try:
                                keys.append(repr(k))
                            except Exception:
                                keys.append(f"<{type(k).__name__}>")
                            if len(keys) >= 3:
                                break
                    return f" at_keys={keys}" if keys else ""
                if isinstance(ref, (list, tuple)):
                    idx = [i for i, v in enumerate(ref) if id(v) == target_id]
                    if len(idx) > 3:
                        idx = idx[:3] + ["…"]
                    return f" at_index={idx}" if idx else ""
            except Exception:
                pass
            return ""

        def is_scheduler_noise(target: Any, ref: Any) -> bool:
            """Plain list/tuple chains (list-in-list, list-in-tuple) and
            list/tuple holding a coroutine are virtually always asyncio
            internals — collections.deque internal block lists, Handle
            args tuples, _ready queue entries.

            Real user code holds objects in lists *attached to a named
            class instance* or *bound to a name in a frame/dict*, so the
            list itself will be reached via that named holder, not via
            a sibling list."""
            if type(target) in (list, tuple) and type(ref) in (list, tuple):
                return True
            if isinstance(target, types.CoroutineType) and type(ref) in (list, tuple):
                return True
            return False

        def is_uninteresting(ref: Any) -> bool:
            """Refs we describe but don't recurse through."""
            if isinstance(ref, _OPAQUE_BOUNDARIES):
                return True
            if type(ref).__name__ in _TRANSIENT_TYPE_NAMES:
                return True
            return False

        # Identify our own coroutine(s) so we don't list ourselves as a
        # referrer. asyncio.current_task().get_coro() returns the Task's
        # *outermost* coroutine, which is wrong when we're called inside
        # an awaited helper — match by code object instead.
        own_code = sys._getframe(0).f_code

        def should_skip_entirely(ref: Any) -> bool:
            """Refs we don't even mention — pure gc noise / ourselves."""
            if type(ref).__name__ in _TRANSIENT_TYPE_NAMES:
                return True
            if isinstance(ref, types.FrameType):
                if ref.f_code in _walker_codes or ref.f_code is own_code:
                    return True
            if isinstance(ref, types.CoroutineType) and ref.cr_code is own_code:
                return True
            return False

        def walk(target: Any, depth: int, on_path: set[int]) -> None:
            if len(seen) >= MAX_NODES:
                truncated.append(f"node-cap reached at depth {depth}")
                return
            if depth > MAX_DEPTH:
                truncated.append(f"depth-cap at {describe(target)[:60]}")
                return

            tid = id(target)
            on_path.add(tid)
            try:
                referrers = gc.get_referrers(target)
                referrers_id = id(referrers)  # exclude this transient list

                shown = 0
                hidden = 0
                for ref in referrers:
                    if id(ref) == referrers_id:
                        continue
                    if should_skip_entirely(ref):
                        continue
                    if is_scheduler_noise(target, ref):
                        continue

                    if shown >= MAX_REFS_PER_NODE:
                        hidden += 1
                        continue

                    rid = id(ref)
                    indent = "  " * depth
                    desc = describe(ref)
                    where = held_at(ref, tid)

                    nonlocal cycles
                    if rid in on_path:
                        cycles += 1
                        back_to = seen.get(tid, "?")
                        print(f"{indent}↺ CYCLE → back to {back_to}: {desc}{where}")
                        continue
                    if rid in seen:
                        print(f"{indent}↗ shared {seen[rid]}: {desc}{where}")
                        continue

                    lbl = label_for(ref)
                    print(f"{indent}{lbl} ← {desc}{where}")
                    shown += 1

                    if not is_uninteresting(ref):
                        walk(ref, depth + 1, on_path)

                if hidden:
                    print(f"{'  ' * depth}… +{hidden} more referrers (capped)")
            finally:
                on_path.discard(tid)

        _walker_codes = {
            walk.__code__, describe.__code__, held_at.__code__,
            label_for.__code__, is_uninteresting.__code__,
            should_skip_entirely.__code__, is_scheduler_noise.__code__,
        }

        rc = sys.getrefcount(ob) - 1
        print(f"--- Refgraph for {type(ob).__qualname__} "
              f"id={obj_id} refcount={rc} ---")
        label_for(ob)
        print(f"#1 ROOT {type(ob).__module__}.{type(ob).__qualname__}")
        walk(ob, 1, set())
        print(f"--- {len(seen)} nodes, {cycles} cycle edge(s), "
              f"{len(truncated)} truncation(s) ---")
        for t in truncated[:5]:
            print(f"    truncated: {t}")

        # ---------- frame-local clearing (original behaviour) ----------
        active_frames: set[types.FrameType] = set()
        for task in asyncio.all_tasks():
            coro = getattr(task, "_coro", None)
            while coro is not None:
                frame = getattr(coro, "cr_frame", None)
                if frame is not None:
                    active_frames.add(frame)
                coro = getattr(coro, "cr_await", None)

        for frame_obj in gc.get_referrers(ob):
            if not isinstance(frame_obj, types.FrameType):
                continue
            if module_filter and module_filter not in frame_obj.f_code.co_filename:
                continue
            if frame_obj in active_frames:
                continue
            if frame_obj.f_code in _walker_codes or frame_obj.f_code is own_code:
                continue
            try:
                for var_name, var_value in frame_obj.f_locals.items():
                    if id(var_value) == obj_id:
                        print(f"Clearing frame {frame_obj.f_code.co_name}:{frame_obj.f_lineno} var={var_name}")
                        frame_obj.f_locals[var_name] = None
                        destroyed += 1
                        break
            except Exception as e:
                print(f"Error nuking frame: {str(e)}")
        return destroyed