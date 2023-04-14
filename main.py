import sys
import asyncio
from mitmproxy_server import start_proxy

def main():
    host=sys.argv[1]
    port=int(sys.argv[2])
    asyncio.run(start_proxy(host, port))


if __name__ == '__main__':
    main()