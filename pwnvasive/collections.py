from collections import OrderedDict,Counter
from itertools import islice
from .mappings import Mapping
from .events import EventCreate,EventUpdate,EventDelete

class Collection(object):
    def __init__(self, store, mapping, lst=None):
        self.mapping = mapping
        self.store = store
        if lst is None:
            lst = []
        keys = [x.key for x in lst]
        if len(set(keys)) != len(keys):
            dups = [k for k,c in Counter(keys).items() if c > 1]
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
            except Exception: # pylint: disable=broad-except
                pass
            else:
                try:
                    o = next(islice(self.coll.values(), selector, None))
                    return o.key
                except StopIteration as e:
                    raise KeyError(selector) from e
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
    def __setitem__(self, key, item):
        self.coll[key] = item
    def pop(self, key):
        return self.coll.pop(key)

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
            raise KeyError("Object already present: {obj}")
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
