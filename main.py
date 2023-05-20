from urllib.parse import urlparse
import sys
import asyncio
import constants
from bin.reporting import start_reporting_ui

constants.APP_SCOPE = urlparse(sys.argv[3]).netloc  # sets the scope of the app

from mitmproxy_server import start_proxy


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    asyncio.run(start_proxy(host, port))


if __name__ == "__main__":
    main()
    # start_reporting_ui()
