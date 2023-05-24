from urllib.parse import urlparse
import sys
import threading
import constants
from bin.reporting import start_reporting_ui
import os

constants.APP_SCOPE = urlparse(sys.argv[3]).netloc  # sets the scope of the app

from mitmproxy_server import start_proxy


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    # Delete the DB file if it exists
    try:
        os.remove('reporting.sqlite')
    except OSError:
        pass

    thread1 = threading.Thread(target=start_proxy, args=(host, port,))
    thread1.start()
    start_reporting_ui()
    thread1.join()


if __name__ == "__main__":
    main()
