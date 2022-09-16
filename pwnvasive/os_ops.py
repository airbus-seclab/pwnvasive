import asyncio
import re

class OS(object):
    def __init__(self, node):
        self.node = node

class Linux(OS):
    @property
    def filename_collection(self):
        return self.node.store.linuxfiles

    async def run(self, cmd):
        sout,_serr = await self.node.run(cmd)
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

    re_arpcache = re.compile(r"\(([0-9.]+)\) at ([0-9a-fA-F:]+) .* on ([0-9a-zA-Z]+)")
    async def get_arp_cache(self):
        out = await self.run("arp -an")
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

