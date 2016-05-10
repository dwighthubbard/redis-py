from .client import Redis, StrictRedis
from .connection import Connection, SSLConnection
from .utils import from_url
from .exceptions import AuthenticationError,BusyLoadingError, ConnectionError, DataError, InvalidResponse, PubSubError,\
    ReadOnlyError, RedisError, ResponseError, TimeoutError, WatchError

__version__ = '2.10.5'
VERSION = tuple(map(int, __version__.split('.')))

__all__ = [
    'Redis', 'StrictRedis',
    'Connection', 'SSLConnection', 'from_url',
    'AuthenticationError', 'BusyLoadingError', 'ConnectionError', 'DataError',
    'InvalidResponse', 'PubSubError', 'ReadOnlyError', 'RedisError',
    'ResponseError', 'TimeoutError', 'WatchError'
]
