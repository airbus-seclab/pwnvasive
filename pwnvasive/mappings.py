import asyncio
import asyncssh
import base64
import zlib
from itertools import islice
from ipaddress import ip_address,ip_network

from .os_ops import *
from .exceptions import *
from .events import *

### Mappings

class MappingMeta(type):
    def __new__(cls, name, bases, dct):
        _k = dct.get("_key")
        _f = dct.get("_fields")
        if _k is None:
            if _f:
                _k = (next(islice(_f.keys(), 1)),)
                dct["_key"] = _k
        _kt = dct.get("_keytype")
        if _kt is None and _k is not None:
            _kt = tuple(_f[k][1] for k in _k)
            dct["_keytype"] = _kt
        return super().__new__(cls, name, bases, dct)

class Mapping(object, metaclass=MappingMeta):
    _fields = {}
    _key = None # tuple. If None, metaclass will use the first field of _field.
    _keytype = None # automatically computed from _key and _fields by metaclass
    _is_cache = []
    def __init__(self, store=None, **kargs):
        self.store = store
        self.values = {}
        for f,(v,_) in self._fields.items():
            if type(v) in [list, dict]:
                v = v.copy()
            self.values[f] = kargs.pop(f, v)
    def __getattr__(self, attr):
        if attr in self.values:
            return self.values[attr]
        raise AttributeError(attr)
    def __getitem__(self, item):
        return self.values[item]
    async def flush(self):
        for k in self._is_cache:
            v = self._fields[k][0]
            if type(v) in [list, dict]:
                v = v.copy()
            self.values[k] = v
    @property
    def key(self):
        # _key is populated by metaclass if None
        # pylint: disable=not-an-iterable
        return tuple(self.values[x] for x in self._key) 
    @classmethod
    def str2key(cls, s):
        return tuple(t(v) for t,v in zip(cls._keytype, s.split(":")))
    @property
    def key_as_str(self):
        # _key is populated by metaclass if None
        # pylint: disable=not-an-iterable
        return ":".join(str(self.values.get(k, "")) for k in self._key)
    @property
    def shortname(self):
        return self.key_as_str
    def update(self, other):
        for f in self._fields:
            if f in other:
                self.values[f] = other[f]
    @classmethod
    def from_json(cls, j, store=None):
        return cls(store=store, **j)
    def to_json(self):
        return self.values
    def __json__(self):
        return self.to_json()
    def __repr__(self):
        return self.summary()
    def summary(self, include=None, exclude=[], other=[]):
        def fmtval(v):
            if type(v) is list:
                return [fmtval(x) for x in v]
            if type(v) is dict:
                return {k:fmtval(v) for k,v in v.items()}
            v = f"{v}".strip()
            if len(v) > 20:
                v = f"{v[:5]}...({len(v)})...{v[-5:]}"
            return v
        r = ", ".join(f"{k}={fmtval(v)}" for k,v in self.values.items()
                      if v is not None and k not in exclude and (include is None or k in include))
        return "<%s>" % (" ".join([r]+other))




class Net(Mapping):
    _fields = {
        "cidr": ("127.0.0.1/32", str),
        "scanned": (False, bool),
    }
    _is_cache = ["scanned"]

class Login(Mapping):
    _fields = {
        "login": (None, str),
    }

class Password(Mapping):
    _fields = {
        "password": (None, str),
    }

class SSHKey(Mapping):
    _fields = {
        "sshkey": (None, str),
        "origin": (None, str),
    }
    _sshkey = None
    def __init__(self, **kargs):
        super().__init__(**kargs)
        try:
            self._sshkey = asyncssh.import_private_key(self.sshkey)
        except asyncssh.KeyImportError:
            pass
        if self._sshkey is None:
            self.find_passphrase()
    @property
    def shortname(self):
        return repr(self)[1:-1]

    def test_key_passphrase(self, pwd):
        try:
            asyncssh.import_private_key(self.sshkey, passphrase=pwd)
        except asyncssh.KeyEncryptionError:
            return False
        return True


    def find_passphrase(self, passwords=None):
        if passwords is None:
            passwords = [p.password for p in self.store.passwords]
        for p in passwords:
            if self.test_key_passphrase(p):
                found = p
                break
        else:
            return False
        self._sshkey = asyncssh.import_private_key(self.sshkey, found)
        # store decrypted key ; use pkcs1-pem for determinism
        self.values["sshkey"] = self._sshkey.export_private_key(format_name="pkcs1-pem").decode("ascii")
        self.store.sshkeys.rehash()
        self.store.notify(EventUpdate(self))
        return True

    def __repr__(self):
        dec = "encrypted" if self._sshkey is None else "decrypted"
        if self._sshkey:
            h = self._sshkey.get_fingerprint()
            c = self._sshkey.get_comment()
            a = self._sshkey.get_algorithm()
        else:
            h = c = a = "(-)"
        return f"<{dec} ssh key: {a} {h} {c} {self.origin}>"

class LinuxFile(Mapping):
    _fields = {
        "path": ("", str),
    }
    def __repr__(self):
        return f"<path={self.path}>"

class Node(Mapping):
    _key = ("ip", "port")
    _fields = {
        "ip":                  ("127.0.0.1", str),
        "port":                (22, int),
        "reachable":           (None, bool),
        "controlled":          (None, bool),
        "jump_host":           (None, str),
        "hostname":            (None, str),
        "routes":              ([], list),
        "arp_cache":           ({}, dict),
        "tested_credentials":  ([], list),
        "working_credentials": ([], list),
        "os":                  (None, str),
        "files":               ({}, dict),
    }
    _is_cache = ["reachable", "controlled", "tested_credentials"]

    def __init__(self, **kargs):
        super().__init__(**kargs)
        self._reached = self.values.get("reachable")
        self._session = None
        self._sftp = None
        self._os = None
        self._lock_reached = asyncio.Lock()
        self._lock_session = asyncio.Lock()
        self._lock_sftp = asyncio.Lock()
        self._lock_os = asyncio.Lock()
        self._semaphore_ssh_limit = asyncio.Semaphore(10) # limit to 10 concurrent ssh operations

        if self.values.get("os") == "linux":
            self._os = Linux(self)

    def __repr__(self):
        other =[]
        username = self.working_credentials[0].get("username") if self.working_credentials else None
        if username:
            other.append(f"username={username}")
        other.append(f"files={len(self.files)}")
        return self.summary(exclude=["files", "routes", "arp_cache", "tested_credentials", "working_credentials"], other=other)

    @property
    def nodename(self):
        return self.hostname or self.ip

    @property
    def in_scope(self):
        scope = self.store.config.get("scope",[])
        if not scope:
            return True
        ip = ip_address(self.ip)
        for p in scope:
            if ip in ip_network(p):
                return True
        return False

    async def flush(self):
        await super().flush()
        async with self._lock_reached:
            self._reached = None

    async def get_reached(self):
        async with self._lock_reached:
            if self._reached is None:
                if not self.in_scope:
                    raise NodeUnreachable(f"Node [{self.nodename}] is out of perimeter (see 'config')")
                if self.jump_host is None:
                    try:
                        _r,w = await asyncio.open_connection(self.ip, self.port)
                    except OSError as e:
                        if e.errno != 111:
                            raise
                        self._reached = False
                    else:
                        self._reached = True
                        w.close()
                else:
                    try:
                        jh = self.store.nodes[self.jump_host]
                    except KeyError as e:
                        raise Exception(f"Jump host not found in node list: {self.jump_host}") from e
                    jhs = await jh.connect()
                    try:
                        c,_s = await jhs.create_connection(asyncssh.SSHTCPSession, self.ip,self.port)
                    except asyncssh.ChannelOpenError:
                        self._reached = False
                    else:
                        self._reached = True
                        c.close()
                if self._reached:
                    self.store.notify(EventNodeReached(self))
            self.values["reachable"] = self._reached
            return self._reached

    async def _test_creds(self, **creds):
        use_creds = creds.copy()
        ck = use_creds.pop("client_keys",None)
        if ck:
            use_creds["client_keys"] = asyncssh.import_private_key(ck)
        opt = asyncssh.SSHClientConnectionOptions(**use_creds, known_hosts=None)
        if self.jump_host:
            jh = await self.store.nodes[self.jump_host].connect()
        else:
            jh = None
        try:
            async with self._semaphore_ssh_limit:
                sess = await asyncssh.connect(host=self.ip, port=self.port, options=opt, tunnel=jh)
        except asyncssh.PermissionDenied:
            return creds,False,None
        except Exception:
            return creds,False,None
        return creds,True,sess

    async def get_session(self):
        if not self.in_scope:
            raise NodeUnreachable(f"Node [{self.nodename}] is out of perimeter (see 'config')")
        reached = await self.get_reached()
        if not reached:
            raise NodeUnreachable(f"cannot reach {self.shortname}")
        async with self._lock_session:
            if self._session is None:
                if not self.working_credentials:
                    c0 = [{"username":l.login} for l in self.store.logins]
                    c1 = [{"username":l.login, "password":l.login} for l in self.store.logins]
                    c2 = [{"username":l.login, "password":p.password}
                          for l in self.store.logins for p in self.store.passwords]
                    c3 = [{"username":l.login, "client_keys": s.sshkey}
                          for l in self.store.logins for s in self.store.sshkeys if s._sshkey]
                    creds = (c for c in c0+c1+c2+c3 if c not in self.tested_credentials)
                    res = await asyncio.gather(*[self._test_creds(**c) for c in creds])
                    self.tested_credentials.extend([cred for cred,r,_ in res if not r])
                    self.working_credentials.extend([cred for cred,r,_ in res if r])
                    if not self.working_credentials:
                        self.values["controlled"] = False
                        raise NoCredsFound(self.shortname)
                    for _,r,sess in res:
                        if r:
                            self._session = sess
                            break
                    self.store.notify(EventNodeConnected(self))
                else:
                    _,_,sess = await self._test_creds(**self.working_credentials[0])
                    self._session = sess
            self.values["controlled"] = True
            return self._session

    async def get_os(self):
        async with self._lock_os:
            if self._os is None:
                async with self._semaphore_ssh_limit:
                    session = await self.get_session()
                    r = await session.run("uname -o")
                if "linux" in r.stdout.lower():
                    self._os = Linux(self)
                    self.values["os"] = "linux"
                    self.values["hostname"] = await self._os.get_hostname()
                    self.store.notify(EventNodeIdentified(self))
                else:
                    raise OSNotIdentified(f"Could not recognize os [{r.stdout.strip()}]")
            return self._os

    async def get_sftp_session(self):
        async with self._lock_sftp:
            if self._sftp is None:
                session = await self.get_session()
                self._sftp = await session.start_sftp_client()
        return self._sftp

    async def disconnect(self):
        async with self._lock_session:
            if self._session:
                self._session.close()
                self._session = None
                return True
            return False

    def remember_file(self, path, content):
        c = base64.b85encode(zlib.compress(content)).decode("ascii")
        if path in self.files:
            if self.files[path] == c:
                return
        self.files[path] = c
        self.store.notify(EventNodeFile(self, path=path))

    def recall_file(self, path):
        c = self.files[path]
        return zlib.decompress(base64.b85decode(c.encode("ascii")))

    def iter_files(self):
        for f,c in self.files.items():
            c2 = zlib.decompress(base64.b85decode(c.encode("ascii")))
            yield f,c2

    async def connect(self):
        return await self.get_session()

    async def identify(self):
        await self.get_os()

    async def run(self, cmd):
        session = await self.get_session()
        async with self._semaphore_ssh_limit:
            r = await session.run(cmd)
        return r.stdout, r.stderr

    async def glob(self, pattern):
        sftp = await self.get_sftp_session()
        async with self._semaphore_ssh_limit:
            return await sftp.glob(pattern)

    async def get(self, path):
        sftp = await self.get_sftp_session()
        async with self._semaphore_ssh_limit:
            async with sftp.open(path, "rb") as f:
                content = await f.read()
        self.remember_file(path, content)
        return content

    async def mget(self, *paths):
        sftp = await self.get_sftp_session()
        try:
            async with self._semaphore_ssh_limit:
                lst = await sftp.glob(paths, error_handler=lambda x:None)
        except asyncssh.SFTPNoSuchFile:
            return {}
        filtered_lst = [f for f in lst if f not in self.files]
        contents = await asyncio.gather(*(self.get(f) for f in filtered_lst), return_exceptions=True)
        d = { k:v for k,v in zip(filtered_lst, contents) if type(v) is bytes }
        return d

    async def collect_files(self, lst=None):
        if lst is None:
            fname_coll = await self.get_filename_collection()
            lst = [f.path for f in fname_coll]
        return await self.mget(*lst)

    async def collect_logins(self):
        os = await self.get_os()
        return await os.collect_logins()

    async def collect_filenames(self):
        os = await self.get_os()
        return await os.collect_filenames()

    async def collect_infos(self):
        os = await self.get_os()
        return await os.get_all()

    async def collect_routes(self):
        os = await self.get_os()
        routes = await os.get_routes()
        self.values["routes"] = routes
        self.store.notify(EventNodeRoute(self))
        return routes

    async def collect_arp_cache(self):
        os = await self.get_os()
        cache = await os.get_arp_cache()
        self.values["arp_cache"] = cache
        self.store.notify(EventNodeARPCache(self))
        return cache

    async def get_filename_collection(self):
        os = await self.get_os()
        return os.filename_collection

