#!/bin/env python
from mitmproxy import options
from mitmproxy.tools import dump
from mitmproxy_addons import *
import asyncio
from constants import PROXY_HOST, PROXY_PORT


async def build_proxy():
    opts = options.Options(listen_host=PROXY_HOST, listen_port=PROXY_PORT)

    master = dump.DumpMaster(
        opts,
        with_termlog=True,
        with_dumper=False,
    )
    # master.addons.add(RequestLogger(), RerouteAgent(), IdorAttack())
    master.addons.add(IdorAttack(), JWTNoneAlgAttack(), SSRFAttack())
    print('Running proxy...')
    await master.run()
    return master


def start_proxy():
    asyncio.run(build_proxy())