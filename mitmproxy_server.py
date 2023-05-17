#!/bin/env python
from mitmproxy import options
from mitmproxy.tools import dump
from mitmproxy_addons import *

async def start_proxy(host, port):
    opts = options.Options(listen_host=host, listen_port=port)

    master = dump.DumpMaster(
        opts,
        with_termlog=False,
        with_dumper=False,
    )
    # master.addons.add(RequestLogger(), RerouteAgent(), IdorAttack())
    master.addons.add(IdorAttack(), JWTNoneAlgAttack())
    
    await master.run()
    return master
