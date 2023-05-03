from mitmproxy import http
from helpers import replay_flow
from constants import URL_REGEX_STRING, PATH_REGEX_STRING
import re, requests, tldextract

class RerouteAgent:
    # sample add-on that reroutes the request or stops it according to certain rules
    def request(self, flow: http.HTTPFlow):
        # redirect to different host
        if flow.request.pretty_host == "google.com":
            flow.request.host = "mitmproxy.org"
        # answer from proxy
        elif flow.request.path.endswith("/brew"):
            flow.response = http.Response.make(
                418, b"I'm a teapot",
            )


class RequestLogger:
    # sample add-on that prints the request passing through
    def request(self, flow: http.HTTPFlow):
        print(flow.request)


class OpenRedirectionAttack:
    REF_ATTACK_URL = 'http://google.com'
    ATTACK_LABEL = 'OPEN_REDIRECTION'

    def is_param_testable(self, param):
        param_name, param_value = param
        for REGEX in [ URL_REGEX_STRING, PATH_REGEX_STRING ]:
            if re.match(REGEX, param_value):
                return True
        return False
    

    def is_attack_successful(self, flow: http.HTTPFlow):
        return tldextract.extract(flow.request.url).domain == tldextract.extract(self.REF_ATTACK_URL).domain


    def request(self, flow: http.HTTPFlow):
        if hasattr(flow.request, 'ignore'):
            return
        
        pairs_with_urls = [ pair for pair in flow.request.query.items() if self.is_param_testable(pair) ]
        for param_name, param_value in pairs_with_urls:
            print('open redirection?')
            attack_flow = flow.copy()
            attack_flow.request.label = self.ATTACK_LABEL
            attack_flow.request.query[param_name] = self.REF_ATTACK_URL
            attack_flow.request.ignore = True
            # print(attack_flow.request.query)
            replay_flow(attack_flow, self.ATTACK_LABEL)
    

    def response(self, flow: http.HTTPFlow):
        if flow.request.label == self.ATTACK_LABEL:
            # print(flow.request.host, flow.request.pretty_url, flow.request.url)
            print(self.ATTACK_LABEL, 'Response')
            if self.is_attack_successful(flow):
                print(self.ATTACK_LABEL, 'SUCCESS!!')
