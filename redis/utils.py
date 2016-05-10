HIREDIS_AVAILABLE = False


def from_url(url, db=None, **kwargs):
    """
    Returns an active Redis client generated from the given database URL.

    Will attempt to extract the database id from the path url fragment, if
    none is provided.
    """
    from redis.client import Redis
    return Redis.from_url(url, db, **kwargs)


class dummy(object):
    """
    Instances of this class can be used as an attribute container.
    """
    pass
