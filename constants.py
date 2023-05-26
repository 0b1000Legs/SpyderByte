DOMAIN_REGEX_STRING = r'^([a-zA-Z]+://)?([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}'
IP_REGEX_STRING = r'^([a-zA-Z]+://)?(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}|localhost)'  # also localhost
PATH_REGEX_STRING = r'^(\/[a-zA-Z0-9\-\_]+)+|([a-zA-Z0-9\-\_]+\/)+([a-zA-Z0-9\-\_]+)?\/?$'
PROXY_HOST = ''
PROXY_PORT = ''
APP_SCOPE = ''
DETECTOR_SERVER_HOST = '127.0.0.1'
DETECTOR_SERVER_PORT = 9999