from mitmproxy import http
from helpers import replay_flow, is_request_in_scope
from constants import URL_REGEX_STRING, PATH_REGEX_STRING
import re, tldextract, json, hashlib

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
        pass
        print(flow.request)
        if flow.request.path == '/':
            print(dict(flow.request.cookies) == dict(flow.request.cookies))
        print(flow.request.query)
        print(flow.request.path_components)


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
        if hasattr(flow.request, 'label') and flow.request.label == self.ATTACK_LABEL:
            # print(flow.request.host, flow.request.pretty_url, flow.request.url)
            print(self.ATTACK_LABEL, 'Response')
            if self.is_attack_successful(flow):
                print(self.ATTACK_LABEL, 'SUCCESS!!')

 
class IdorAttack:
    ATTACK_LABEL = 'IDOR'
    user_endpoints_map = {}

    def is_identifier(self, content):
        try:
            int(content)
            return True
        except:
            return False


    def get_request_token(self, flow: http.HTTPFlow):
        if len(flow.request.path_components) and not self.is_identifier(flow.request.path_components[-1]):
            return
        return '/'.join(flow.request.path_components[:-1])
    

    def get_user_session_fingerprint(self, flow: http.HTTPFlow):
        cookies_serialized = json.dumps(dict(flow.request.cookies))
        return hashlib.md5(cookies_serialized.encode('utf-8')).hexdigest()
    

    def get_response_fingerprint(self, flow: http.HTTPFlow):
        if flow.request.text:
            return hashlib.md5(flow.request.text.encode('utf-8')).hexdigest()
        return None


    def add_endpoint_tracking(self, flow: http.HTTPFlow, request_token):
        request_path_object = self.user_endpoints_map.get(request_token)
        
        if not request_path_object:
            self.user_endpoints_map[request_token] = {
                'ignore_path': False,
                'sub_paths': {
                    flow.request.path: {
                        'flow': flow,
                        'owner': self.get_user_session_fingerprint(flow),
                    },
                },
            }
            return
        
        if request_path_object['ignore_path']:
            return

        if not request_path_object['sub_paths'].get(flow.request.path):
            request_path_object['sub_paths'][flow.request.path] = {
                'flow': flow,
                'owner': self.get_user_session_fingerprint(flow)
            }
            
            if len(request_path_object['sub_paths'].keys()) > 2:
                request_path_object['ignore_path'] = True
            return
        
        if request_path_object['sub_paths'][flow.request.path]['owner'] != self.get_user_session_fingerprint(flow):
            request_path_object['ignore_path'] = True


    def is_idor_possible(self, request_token):
        if self.user_endpoints_map.get(request_token)['ignore_path']:
            return False
        
        paths = self.user_endpoints_map.get(request_token)['sub_paths']
        # print("___________TESTING: ", request_token, paths.keys())
        return len(paths.keys()) == 2 and len(set(obj['owner'] for obj in paths.values())) == 2


    def is_attack_successful(self, flow: http.HTTPFlow):
        return self.get_response_fingerprint(flow) == flow.request.TARGET_RESP_FINGERPRINT


    def request(self, flow: http.HTTPFlow):
        if hasattr(flow.request, 'ignore'):
            return
        # print(self.get_user_session_fingerprint(flow), '|', is_request_in_scope(flow), '|', flow.request)


    def response(self, flow: http.HTTPFlow):
        if hasattr(flow.request, 'label') and flow.request.label == self.ATTACK_LABEL:
            if self.is_attack_successful(flow):
                print('FOUND IDOR in ', flow.request.path)
            return
        
        request_token = self.get_request_token(flow)

        if not is_request_in_scope(flow) or not request_token:
            return

        self.add_endpoint_tracking(flow, request_token)
        # print(self.user_endpoints_map)

        if self.is_idor_possible(request_token):
            # test idor here
            print('********** IDOR possible in: ', request_token)
            
            other_path_obj = [
                path_obj for path_obj
                in self.user_endpoints_map.get(request_token)['sub_paths'].items()
                if path_obj[0] != flow.request.path
            ][0][1]
            
            # print('_____sibling:', other_path_obj)
            
            target_flow = other_path_obj['flow']
            attack_flow = flow.copy()
            attack_flow.request.label = self.ATTACK_LABEL
            attack_flow.request.TARGET_RESP_FINGERPRINT = self.get_response_fingerprint(target_flow)
            replay_flow(attack_flow, self.ATTACK_LABEL)
