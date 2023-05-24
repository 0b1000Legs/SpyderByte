#!/bin/env python
from mitmproxy import options
from mitmproxy.tools import dump
from mitmproxy_addons import *
import asyncio


async def build_proxy(host, port):
    opts = options.Options(listen_host=host, listen_port=port)

    master = dump.DumpMaster(
        opts,
        with_termlog=True,
        with_dumper=False,
    )
    # master.addons.add(RequestLogger(), RerouteAgent(), IdorAttack())
    master.addons.add(IdorAttack(), JWTNoneAlgAttack(), RequestLogger())
    print('Running proxy...')
    await master.run()
    return master


def start_proxy(host, port):
    asyncio.run(build_proxy(host, port))