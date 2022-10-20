import asyncio
from enum import Enum

class State(Enum):
    STARTED = "started"
    STOPPED = "stopped"
    STARTING = "starting"
    STOPPING = "stopping"

class MetaService(type):
    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)
        if self.__name__ != "Service":
            self.all_services[self.__name__]=  self

class Service(object, metaclass=MetaService):
    all_services = {}
    def __init__(self, options):
        self.options = options
        self.state = State.STOPPED
        self.state_lock = asyncio.Lock()
    @property
    def started(self):
        return self.state == State.STARTED
    @property
    def stopped(self):
        return self.state == State.STOPPED
    @property
    def status(self):
        return self.state.value
    async def start(self):
        async with self.state_lock:
            if self.state != State.STARTED:
                self.state = State.STARTING
                await self.do_start()
                self.state = State.STARTED
    async def stop(self):
        async with self.state_lock:
            if self.state != State.STOPPED:
                self.state = State.STOPPING
                await self.do_stop()
                self.state = State.STOPPED
    async def restart(self):
        await self.stop()
        await self.start()

    async def __aenter__(self):
        await self.start()
        return self
    async def __aexit__(self):
        await self.stop()

    async def do_start(self):
        raise NotImplementedError
    async def do_stop(self):
        raise NotImplementedError
