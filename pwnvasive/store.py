import asyncio
import json
import os
from collections import defaultdict
import prompt_toolkit

from .mappings import Net,Node,Login,Password,SSHKey,LinuxFile
from .collections import Collection
from .exceptions import *

class JSONEnc(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, "__json__"):
            return o.__json__()
        return json.JSONEncoder.default(self, o)



DEFAULT_STORE = {
    "meta": { "version": "0.1", },
    "state": {},
    "history": [],
    "config" : {
        "scope": [],
    }
}

class Store(object):
    _objects = {
        "networks": Net,
        "nodes": Node,
        "logins": Login,
        "passwords": Password,
        "sshkeys": SSHKey,
        "linuxfiles": LinuxFile,
    }
    def __init__(self, fname=None, json_=None):
        self.eventq = asyncio.Queue()
        self.callbacks = defaultdict(lambda : defaultdict(set))
        self.fname = fname
        if json_ is not None:
            j = json_
        elif fname and os.path.isfile(fname):
            with open(fname, encoding="utf8") as f:
                j = json.load(f)
        else:
            j = DEFAULT_STORE
        self.store = j
        self.config = self.store.get("config",{})
        s = self.store["state"]
        self.objects = {}
        for f,c in self._objects.items():
            self.objects[f] = Collection(self, c, [c.from_json(d, store=self)
                                                   for d in  s.get(f,[])])
        self.history = prompt_toolkit.history.InMemoryHistory()
        for l in j.get("history",[]):
            self.history.append_string(l)

        self.dispatcher_task = asyncio.create_task(self.event_dispatcher(), name="Event Dispatcher")

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
        self.store["state"].update(self.objects)
        self.store["history"] = self.history.get_strings()
        with open(fname+".tmp", "w", encoding="utf8") as f:
            json.dump(self.store, f, indent=4, cls=JSONEnc)
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
                        _task = asyncio.create_task(cb(event), name=f"handler {cb}")
