import sys
import asyncio
import signal
import json
from aiocmd import aiocmd
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.completion import WordCompleter,NestedCompleter,PathCompleter
import pdb

from .events import Event,EventUpdate
from .exceptions import *
from .mappings import Mapping

### Subclass aiocmd to pass arguments to PromptSession


class CmdWithCustomPromptSession(aiocmd.PromptToolkitCmd):
    async def run(self, **session_kargs):
        if self._ignore_sigint and sys.platform != "win32":
            asyncio.get_event_loop().add_signal_handler(signal.SIGINT, self._sigint_handler)
        self.session = PromptSession(enable_history_search=True,
                                     key_bindings=self._get_bindings(),
                                     **session_kargs)
        try:
            with patch_stdout():
                await self._run_prompt_forever()
        finally:
            if self._ignore_sigint and sys.platform != "win32":
                asyncio.get_event_loop().remove_signal_handler(signal.SIGINT)
            self._on_close()

###

class PwnCLI(CmdWithCustomPromptSession):
    # pylint: disable=broad-except
    def __init__(self, options):
        self.options = options
        self.store = options.store
        self.prompt = "pwnvasive > "
        self.op = options.operations
        self.handlers = options.handlers
        super().__init__()
        self.sessions = []


    def str2map(self, s):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return { k.strip():v.strip()
                     for k,v in [x.strip().split("=",1) for x in s.split(" ")] }



    def obj_selector_completer(self):
        return NestedCompleter({
            coll: NestedCompleter({
                obj.key_as_str: None
                for obj in self.store.objects[coll]
            })
            for coll in self.store._objects
        })

    def selector_completer(self, collection):
        return WordCompleter(["*"]+[x.key_as_str for x in collection])

    def do_save(self, fname=None):
        self.store.save(fname)

    def _save_completions(self):
        return PathCompleter(expanduser=True)

    def do_config(self, key=None, op=None, val=None):
        if key is None:
            for k,v in self.store.config.items():
                print(f"{k:15}= {v}")
            return
        else:
            if op is None:
                op = "get"
            if op not in ["get", "empty"] and val is None:
                print("Missing argument")
                return
            if val is not None:
                try:
                    val = json.loads(val)
                except json.JSONDecodeError:
                    pass
            if op == "get":
                print(json.dumps(self.store.config.get(key),indent=4))
            elif op == "set":
                self.store.config[key] = val
            elif op == "add":
                self.store.config[key].append(val)
            elif op == "del":
                self.store.config[key].remove(val)
            elif op == "empty":
                self.store.config[key] = []
            else:
                print(f"Unknonwn operation: {op}")

    def _config_completions(self):
        op = WordCompleter(["get", "set", "add", "del", "empty"])
        return NestedCompleter({k: op for k in self.store.config})


    def do_auto(self, handler=None, on="on"):
        if handler is None:
            for h,s in self.handlers.iter_states():
                print(f"{h:20} {s}")
        else:
            handlers = [handler] if handler != "*" else self.handlers.list()
            for h in handlers:
                if on.lower() in ["on", "1", "ok", "true"]:
                    self.handlers.activate(h)
                elif on.lower() in ["off", "0", "ko", "false"]:
                    self.handlers.deactivate(h)

    def _auto_completions(self):
        onoff = WordCompleter(["on", "off"])
        return NestedCompleter({k:onoff for k in self.handlers.list()})

    async def do_notify(self, obj, selector=None, event=None):
        event = Event.all_events.get(event, EventUpdate)
        for obj in self.store.objects[obj].select(selector):
            self.store.notify(event(obj))

    def _notify_completions(self):
        ev = WordCompleter(list(Event.all_events))
        return NestedCompleter({
            coll: NestedCompleter({
                obj.key_as_str: ev
                for obj in self.store.objects[coll]
            })
            for coll in self.store._objects
        })

    async def do_flush(self, obj, selector=None):
        objs = self.store.objects[obj].select(selector)
        for o in objs:
            print(f"Flushing {o}")
            await o.flush()
        print("Flushing done.")

    def _flush_completions(self):
        return self.obj_selector_completer()

    async def do_disconnect(self, selector=None):
        objs = self.store.nodes.select(selector)
        for x,y in zip(objs, asyncio.as_completed([o.disconnect() for o in objs])):
            disc = await y
            action = "Disconnected:     " if disc else "Left disconnected:"
            print(f"{action} {x}")
        if len(objs) >= 2:
            print(f"All {len(objs)} nodes have been disconnected.")

    def _disconnect_completions(self):
        return self.selector_completer(self.store.nodes)


    ########## DEBUG

    def do_eval(self, cmd):
        # pylint: disable=eval-used
        print(eval(cmd))

    def do_pdb(self):
        # pylint: disable=forgotten-debug-statement
        pdb.set_trace()


    def do_monitor(self, what, onoff="on"):
        start = onoff.lower() in ["on", "1", "true", "ok"]
        stop = onoff.lower() in ["off", "0", "false", "ko"]
        if not (start ^ stop):
            print("ERROR: syntax: event_monitor {on|off}")
            return
        if what == "events":
            if start:
                self.store.register_callback([Event], [Mapping], self.event_monitor)
            else:
                self.store.unregister_callback([Event], [Mapping], self.event_monitor)
        elif what == "handlers":
            if start:
                self.handlers.start_trace(self.handler_monitor)
            else:
                self.handlers.stop_trace()

    def _monitor_completions(self):
        onoff = WordCompleter(["on", "off"])
        return NestedCompleter({k:onoff for k in ["events", "handlers"]})

    async def event_monitor(self, event):
        print(f"MONITOR: {event}")
    def handler_monitor(self, handler, args, kargs):
        print(f"HANDLER: {handler} called with {args} {kargs}")


    def do_tasks(self):
        for t in asyncio.all_tasks():
            print(f"{t.get_name():20} {t.get_coro().cr_code.co_name}")

    ########## MANAGE COLLECTIONS AND MAPPINGS

    def do_ls(self, obj=None, selector=None):
        if obj is None:
            print("\n".join(self.store.objects))
        else:
            if selector is None:
                print(self.store.objects[obj].string_menu())
            else:
                print(self.store.objects[obj][selector])

    def _ls_completions(self):
        return self.obj_selector_completer()

    def do_show(self, obj, selector=None):
        for obj in self.store.objects[obj].select(selector):
            print(f"----- {obj.key} -----")
            print(json.dumps(obj.to_json(), indent=4))

    def _show_completions(self):
        return self.obj_selector_completer()

    def do_add(self, obj, val=""):
        try:
            val = self.str2map(val)
        except Exception:
            print(f"could not parse [{val}]. Should be field=value[,f=v[,...]]")
        else:
            Obj = self.store._objects[obj]
            o = Obj(store=self.store, **val)
            print(f"adding {o}")
            self.store.objects[obj].add(o)

    def _add_completions(self):
        dct = {}
        for k,v in self.store._objects.items():
            d = {f:None for f in v._fields}
            dct[k] = n = NestedCompleter(d)
            for k2 in d:
                d[k2] = n
        return NestedCompleter({
            k: dct[k]
            for k,_ in self.store._objects.items()
        })

    def do_update(self, obj, selector, val):
        try:
            val = self.str2map(val)
        except:
            print(f"could not parse [{val}]. Should be field=value[,f=v[,...]]")
            raise

        objs = self.store.objects[obj].select(selector)
        for o in objs:
            print(f"Updating {o}")
            for f,(_,t) in o._fields.items():
                if f in val:
                    old = o.values.get(f,None)
                    new_ = t(val[f])
                    print(f"  + {f}: {old} --> {new_}")
                    o.values[f] = new_
        self.store.objects[obj].rehash()

    _update_completions = _add_completions

    def do_del(self, obj, selector):
        objs = self.store.objects[obj]
        for o in objs.select(selector):
            print(f"deleting {obj} {o.key}")
            del(objs[o])

    def _del_completions(self):
        return self.obj_selector_completer()


    def do_cat(self, selector, pth):
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            try:
                c = node.recall_file(pth)
            except KeyError:
                pass
            else:
                print(f"----- {node.shortname} -----")
                try:
                    print(c.decode("utf8"))
                except Exception:
                    print(c)

    def _cat_completions(self):
        return NestedCompleter({k.key_as_str: WordCompleter(list(k.files))
                                for k in self.store.nodes})

    ########## CNX

    async def do_cnx(self, selector=None):
        if selector is None:
            for n in self.store.nodes:
                if n.session:
                    print(n.session)
        else:
            nodes = self.store.nodes.select(selector)
            for node in nodes:
                cnx = node.connect()
                t = asyncio.create_task(cnx, name="do_cnx")
                t.add_done_callback(lambda ctx,node=node:self.cb_connected(node, ctx))

    def cb_connected(self, node, t):
        try:
            nsession = t.result()
        except Exception as e:
            print(f"Connection failed: {e}")
        else:
            if nsession:
                print(f"Connected to {node.shortname}")

    def _cnx_completions(self):
        return self.selector_completer(self.store.nodes)

    async def do_id(self, selector=None):
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            cnx = node.identify()
            t = asyncio.create_task(cnx, name="do_id")
            t.add_done_callback(lambda ctx,node=node:self.cb_identified(node, ctx))

    def cb_identified(self, node, t):
        try:
            t.result()
        except Exception as e:
            print(f"Connection failed: {e}")
        else:
            print(f"Identified {node.shortname}")

    def _id_completions(self):
        return self.selector_completer(self.store.nodes)


    ########## RUN

    async def do_run(self, selector, cmd):

        async def run_and_print(node, cmd):
            try:
                sout,_serr = await node.run(cmd)
            except Exception as e:
                print(f"-----[{node.shortname}]-----[ERROR]-----")
                print(e)
            else:
                print(f"-----[{node.shortname}]-----")
                print(sout)

        nodes = self.store.nodes.select(selector)
        _res = await asyncio.gather(*[run_and_print(node, cmd) for node in nodes])

    def _run_completions(self):
        return self.selector_completer(self.store.nodes)


    ######### HARVEST

    async def do_info(self, selector):
        nodes = self.store.nodes.select(selector)
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

    def _info_completions(self):
        return self.selector_completer(self.store.nodes)

    async def do_collect_logins(self, selector):
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(self.op.collect_logins(node), name="do_collect_login")
            t.add_done_callback(lambda ctx,node=node: self.cb_collect_logins(node, ctx))

    def cb_collect_logins(self, node, t):
        _logins,nlog = t.result()
        print(f"{node.shortname}: {nlog} new logins")

    def _collect_logins_completions(self):
        return self.selector_completer(self.store.nodes)


    async def do_collect_filenames(self, selector):
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(self.op.collect_filenames(node), name="do_collect_filenames")
            t.add_done_callback(lambda ctx,node=node:self.cb_collect_filenames(node, ctx))

    def cb_collect_filenames(self, node, t):
        nbold,nbnew = t.result()
        print(f"{node.shortname}: retrieved {nbold} file names. {nbnew} were new.")

    def _collect_filenames_completions(self):
        return self.selector_completer(self.store.nodes)


    async def do_collect_files(self, selector):
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(self.op.collect_files(node), name="do_collect_files")
            t.add_done_callback(lambda ctx,node=node: self.cb_collect_files(node, ctx))

    def cb_collect_files(self, node, t):
        fnames = t.result()
        print(f"{node.shortname}: retrieved {len(fnames)} new files")

    def _collect_files_completions(self):
        return self.selector_completer(self.store.nodes)


    async def do_collect_routes(self, selector):
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(self.op.collect_routes(node), name="do_collect_routes")
            t.add_done_callback(lambda ctx,node=node: self.cb_collect_routes(node, ctx))

    def cb_collect_routes(self, node, t):
        routes = t.result()
        print(f"{node.shortname}: retrieved {len(routes)} routes")

    def _collect_routes_completions(self):
        return self.selector_completer(self.store.nodes)


    async def do_collect_arp_cache(self, selector):
        nodes = self.store.nodes.select(selector)
        for node in nodes:
            t = asyncio.create_task(self.op.collect_arp_cache(node), name="do_collect_arp_cache")
            t.add_done_callback(lambda ctx,node=node: self.cb_collect_arp_cache(node, ctx))

    def cb_collect_arp_cache(self, node, t):
        try:
            cache = t.result()
        except PwnvasiveException as e:
            print(e)
        else:
            print(f"{node.shortname}: retrieved {len(cache)} cache entries")

    def _collect_arp_cache_completions(self):
        return self.selector_completer(self.store.nodes)



    ########## EXTRACT
    def do_extract_ssh_keys(self, selector):
        _okeys,nkeys = self.op.extract_ssh_keys_from_nodes(selector)
        print(f"{nkeys} new potential ssh keys discovered")

    def _extract_ssh_keys_completions(self):
        return self.selector_completer(self.store.nodes)


    def do_decrypt_ssh_keys(self, selector=None):
        n = self.store.op.decrypt_ssh_keys(selector)
        print(f"Decrypted {n} ssh keys")

    def do_extract_networks(self, selector=None):
        nodes = self.store.nodes.select(selector)
        nnets = nnodes = 0
        for node in nodes:
            nnodes += self.op.inspect_arp_cache(node)
            no,ne = self.op.inspect_routes(node)
            nnodes += no
            nnets += ne
            nnodes += self.op.inspect_known_hosts(node)
        print(f"Added {nnets} new networks and {nnodes} new nodes")

    def _extract_networks_completions(self):
        return self.selector_completer(self.store.nodes)


    ########## COMPUTE

    def do_compute_network(self):
        self.op.compute_network()
