import functools
import inspect
import logging
from starlette.responses import StreamingResponse, Response

logger = logging.getLogger(__name__)

def log_function_call(log_args: bool = True, log_return: bool = False, max_str_length: int = 300):
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                func_name = func.__qualname__
                arg_names = inspect.getfullargspec(func).args
                params = dict(zip(arg_names, args))
                params.update(kwargs)

                if log_args:
                    safe_params = {}
                    for k, v in params.items():
                        if isinstance(v, (bytes, bytearray)):
                            safe_params[k] = f"<{type(v).__name__} - {len(v)} bytes>"
                        elif isinstance(v, str) and len(v) > max_str_length:
                            safe_params[k] = v[:max_str_length] + "...(truncated)"
                        else:
                            safe_params[k] = repr(v)
                    logger.debug(f"📥 Called {func_name} with args: {safe_params}")

                result = await func(*args, **kwargs)

                if log_return:
                    if isinstance(result, (StreamingResponse, Response)):
                        logger.debug(f"📤 {func_name} returned: <{result.__class__.__name__}>")
                    else:
                        logger.debug(f"📤 {func_name} returned: {result}")

                return result
            return async_wrapper

        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                func_name = func.__qualname__
                arg_names = inspect.getfullargspec(func).args
                params = dict(zip(arg_names, args))
                params.update(kwargs)

                if log_args:
                    safe_params = {}
                    for k, v in params.items():
                        if isinstance(v, (bytes, bytearray)):
                            safe_params[k] = f"<{type(v).__name__} - {len(v)} bytes>"
                        elif isinstance(v, str) and len(v) > max_str_length:
                            safe_params[k] = v[:max_str_length] + "...(truncated)"
                        else:
                            safe_params[k] = repr(v)
                    logger.debug(f"📥 Called {func_name} with args: {safe_params}")

                result = func(*args, **kwargs)

                if log_return:
                    if isinstance(result, (StreamingResponse, Response)):
                        logger.debug(f"📤 {func_name} returned: <{result.__class__.__name__}>")
                    else:
                        logger.debug(f"📤 {func_name} returned: {result}")

                return result
            return sync_wrapper
    return decorator
