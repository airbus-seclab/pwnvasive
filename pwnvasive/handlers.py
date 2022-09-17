import asyncio
from collections import defaultdict

from .events import *
from .mappings import *
from .exceptions import *


class HandlerRegistry(object):
    callbacks = {}
    @classmethod
    def register(cls, *events_mappings):
        def g(f):
            cls.callbacks[f.__name__] = f
            h = HandlerDescriptor(f, events_mappings)
            return h
        return g
    @classmethod
    def list(cls):
        return list(cls.callbacks)
    def __init__(self, store, operations):
        self.store = store
        self.op = operations
        self.state = defaultdict(bool)
        self._trace_callback = None

    def activate(self, name=None):
        cbs = [name] if name else self.list()
        for cb in cbs:
            getattr(self, cb).activate()
    def deactivate(self, name):
        cbs = [name] if name else self.list()
        for cb in cbs:
            getattr(self, cb).deactivate()
    def iter_states(self):
        for hname,h in self.callbacks.items():
            yield hname, self.state[h]

    def start_trace(self, callback):
        self._trace_callback = callback
    def stop_trace(self):
        self._trace_callback = None

    def trace(self, handler, args, kargs):
        if self._trace_callback:
            self._trace_callback(handler, args, kargs)


class HandlerDescriptor(object):
    def __init__(self, handler, events_mappings):
        self.handler = handler
        self.events_mappings = events_mappings
    def __get__(self, instance, cls):
        return Handler(instance, self.handler, self.events_mappings)

class Handler(object):
    def __init__(self, instance, handler, events_mappings):
        self.instance = instance
        self.handler = handler
        self.events_mappings = events_mappings
        self.__name__ = f"{self.handler.__name__} handler"
    def __call__(self, *args, **kargs):
        self.instance.trace(self, args, kargs)
        return self.handler(self.instance, *args, **kargs)
    def __eq__(self, other):
        return self.instance == other.instance and self.handler == other.handler
    def __hash__(self):
        return hash((self.instance, self.handler))
    def __repr__(self):
        return f"<Event handler for {self.handler.__name__}>"
    def activate(self):
        for events,mappings in self.events_mappings:
            self.instance.store.register_callback(events, mappings, self)
        self.instance.state[self.handler] = True
    def deactivate(self):
        for events,mappings in self.events_mappings:
            self.instance.store.unregister_callback(events, mappings, self)
        self.instance.state[self.handler] = False

class Handlers(HandlerRegistry):

    @HandlerRegistry.register(([EventNodeIdentified],[Node]))
    async def collect_logins(self, event):
        await self.op.collect_logins(event.obj)

    @HandlerRegistry.register(([EventNodeIdentified],[Node]))
    async def collect_routes(self, event):
        await self.op.collect_routes(event.obj)

    @HandlerRegistry.register(([EventNodeIdentified],[Node]))
    async def collect_filenames(self, event):
        await self.op.collect_filenames(event.obj)

    @HandlerRegistry.register(([EventDataModified],[LinuxFile]))
    async def collect_files(self, event):
        await asyncio.gather(*[node.get(event.obj.path) for node in self.store.nodes],
                             return_exceptions=True)

    @HandlerRegistry.register(([EventNodeIdentified],[Node]))
    async def collect_arp_cache(self, event):
        await self.op.collect_arp_cache(event.obj)

    @HandlerRegistry.register(([EventNodeARPCache],[Node]))
    async def inspect_arp_cache(self, event):
        self.op.inspect_arp_cache(event.obj)

    @HandlerRegistry.register(([EventNodeRoute],[Node]))
    async def inspect_routes(self, event):
        self.op.inspect_routes(event.obj)

    @HandlerRegistry.register(([EventNodeFile],[Node]))
    async def inspect_known_hosts(self, event):
        self.op.inspect_routes(event.obj)

    @HandlerRegistry.register(([EventNodeFile],[Node]))
    async def extract_ssh_keys(self, event):
        c = event.obj.recall_file(event.path)
        self.op.extract_ssh_keys_from_content(c)

    @HandlerRegistry.register(([EventDataModified],[SSHKey]))
    async def decrypt_ssh_keys(self, event):
        self.op.decrypt_ssh_keys(event.obj)

    @HandlerRegistry.register(([EventDataModified],[Password]))
    async def decrypt_ssh_keys_with_new_pwd(self, event):
        self.op.decrypt_ssh_keys()

    @HandlerRegistry.register(([EventDataModified,EventNodeConnected],[Node]))
    async def identify_node(self, event):
        try:
            await event.obj.identify()
        except NoCredsFound:
            pass
        except NodeUnreachable:
            pass

    @HandlerRegistry.register(([EventDataModified],[Login, Password, SSHKey]))
    async def try_new_creds(self, _event):
        await asyncio.gather(*(node.connect() for node in self.store.nodes),
                             return_exceptions=True)
