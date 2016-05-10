def iteritems(x):
    return iter(x.items())

def iterkeys(x):
    return iter(x.keys())

def itervalues(x):
    return iter(x.values())

def byte_to_chr(x):
    return chr(x)

def nativestr(x):
    return x if isinstance(x, str) else x.decode('utf-8', 'replace')

def u(x):
    return x

def b(x):
    return x.encode('latin-1') if not isinstance(x, bytes) else x

next = next
unichr = chr
imap = map
izip = zip
xrange = range
basestring = str
unicode = str
safe_unicode = str
bytes = bytes
long = int
