# Hierarchy of events

class EventMetaclass(type):
    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)
        self.all_events[self.__name__] = self

class Event(object, metaclass=EventMetaclass):
    all_events = {}
    def __init__(self, obj, **kargs):
        self.obj = obj
        self._details = kargs
    def __getattr__(self, attr):
        return self._details[attr]
    def __repr__(self):
        return f"<{self.__class__.__name__}({self.obj.shortname})>"

class EventNewContent(Event):
    pass

class EventDataModified(EventNewContent):
    pass

class EventCreate(EventDataModified):
    pass

class EventUpdate(EventDataModified):
    pass

class EventStateModified(EventNewContent):
    pass

class EventNodeReached(EventStateModified):
    pass

class EventNodeConnected(EventStateModified):
    pass

class EventNodeIdentified(EventStateModified):
    pass

class EventNodeNewData(EventDataModified):
    pass

class EventNodeARPCache(EventNodeNewData):
    pass

class EventNodeRoute(EventNodeNewData):
    pass

class EventNodeFile(EventNodeNewData):
    pass

class EventDelete(Event):
    pass
