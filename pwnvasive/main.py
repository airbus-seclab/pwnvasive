#! /usr/bin/env python

import sys
import asyncio
import argparse
import logging
import pdb

from .store import Store
from .operations import Operations
from .handlers import Handlers
from .cli import PwnCLI

logging.basicConfig()
logging.getLogger("asyncio").setLevel(logging.WARNING)



async def aiomain(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("database")

    options = parser.parse_args(args)

    # pylint: disable=broad-except
    try:
        with Store(options.database) as options.store:
            options.operations = Operations(options.store)
            options.handlers = Handlers(options.store, options.operations)
            await PwnCLI(options).run(history=options.store.history)
    except Exception as e:
        print(f"ERROR: {e}")
        print("You can still recover data from options.store.nodes, etc.")
        sys.last_traceback = e.__traceback__
        pdb.pm()

def main(args=None):
    asyncio.run(aiomain(args))

if __name__ == "__main__":
    main()
