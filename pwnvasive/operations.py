import asyncssh
import re
import graphviz
from collections import defaultdict
from ipaddress import ip_address,ip_network
from .mappings import *

class Operations(object):
    def __init__(self, store):
        self.store = store
    async def collect_logins(self, node):
        logins = await node.collect_logins()
        olog = [self.store.logins.mapping(store=self.store, login=l) for l in logins]
        nlog = self.store.logins.add_batch(olog)
        return logins,nlog
    async def collect_routes(self, node):
        return await node.collect_routes()
    async def collect_files(self, node):
        return await node.collect_files()
    async def collect_arp_cache(self, node):
        return await node.collect_arp_cache()
    async def collect_filenames(self, node):
        fnames = await node.collect_filenames()
        coll = await node.get_filename_collection()
        fnameobjects = [coll.mapping(store=self.store, path=p) for p in fnames]
        newfilesnb = coll.add_batch(fnameobjects)
        return len(fnames), newfilesnb
    def inspect_arp_cache(self, node):
        extnodes = []
        for ip in node.arp_cache:
            extnodes.append(Node(store=self.store, ip=ip, jump_host=node.shortname))
        nnodes = self.store.nodes.add_batch(extnodes)
        return nnodes
    def inspect_routes(self, node):
        extnodes = []
        extnets = []
        for r in node.routes:
            dst = r.get("dst")
            if dst and dst != "default":
                extnets.append(Net(store=self.store, cidr=dst))
                gw = r.get("gateway")
                if gw:
                    extnodes.append(Node(store=self.store, ip=gw, jump_host=node.shortname))
        nnodes = self.store.nodes.add_batch(extnodes)
        nnets = self.store.networks.add_batch(extnets)
        return nnodes,nnets
    def inspect_known_hosts(self, content):
        extnodes = []
        try:
            if type(content) is bytes:
                content = content.decode("ascii")
        except UnicodeDecodeError:
            pass
        else:
            try:
                kh = asyncssh.import_known_hosts(content)
            except Exception:
                pass
            else:
                for h in kh._exact_entries.keys():
                    extnodes.append(Node(store=self.store, ip=h, jump_host=node.shortname))
        nnodes = self.store.nodes.add_batch(extnodes)
        return nnodes


    _re_key = re.compile(b"(-----BEGIN ([A-Z0-9 _]*?)PRIVATE KEY-----.*?\n-----END \\2PRIVATE KEY-----)",
                         re.DOTALL)
    def _find_ssh_keys(self, c, origin=None):
        keys = []
        for k,_ in self._re_key.findall(c):
            try:
                k = k.decode("ascii")
            except UnicodeDecodeError:
                continue
            key = SSHKey(store=self.store, sshkey=k, origin=origin)
            keys.append(key)
        return keys

    def extract_ssh_keys_from_content(self, c, origin=None):
        keys = self._find_ssh_keys(c, origin = origin)
        n = self.store.sshkeys.add_batch(keys)
        return len(keys),n

    def extract_ssh_keys_from_node(self, node):
        keys = []
        for pth,c in node.iter_files():
            keys += self._find_ssh_keys(c, origin=f"{node.shortname}:{pth}")
        n = self.store.sshkeys.add_batch(keys)
        return len(keys),n

    def extract_ssh_keys_from_nodes(self, selector):
        keys = []
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            for pth,c in node.iter_files():
                keys += self._find_ssh_keys(c, origin=f"{node.shortname}:{pth}")
        n = self.store.sshkeys.add_batch(keys)
        return len(keys),n

    def decrypt_ssh_keys(self, selector=None):
        keys = self.store.sshkeys.select(selector)
        n = 0
        for k in keys:
            if k._sshkey is None:
                if k.find_passphrase():
                    n += 1
        return n

    def compute_network(self):
        netgraph = defaultdict(set)
        remotes = defaultdict(set)
        ip2name = {}
        for node in self.store.nodes:
            for r in node.routes:
                src = r.get("prefsrc")
                if src:
                    ip2name[src] = node.nodename
        for node in self.store.nodes:
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
