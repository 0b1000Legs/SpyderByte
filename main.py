from urllib.parse import urlparse
import sys
import threading
import constants
from bin.reporting import start_reporting_ui
from bin.detection_server.server import run_detection_server
import os

constants.APP_SCOPE = urlparse(sys.argv[3]).netloc  # sets the scope of the app
constants.PROXY_HOST = sys.argv[1]
constants.PROXY_PORT = int(sys.argv[2])

from mitmproxy_server import start_proxy


def main():
    # Delete the DB file if it exists
    try:
        os.remove('reporting.sqlite')
    except OSError:
        pass

    thread1 = threading.Thread(target=start_proxy)
    thread2 = threading.Thread(target=run_detection_server, args=(constants.DETECTOR_SERVER_HOST, constants.DETECTOR_SERVER_PORT))
    thread1.start()
    thread2.start()
    start_reporting_ui()
    thread1.join()
    thread2.join()


if __name__ == "__main__":
    main()
