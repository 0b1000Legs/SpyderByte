import base64
import json
import re
from mitmproxy import ctx, http
from constants import APP_SCOPE
from urllib.parse import urlparse


# returns a clone of the original request with no modifications, exists as a sample builder method
def clone_request(flow: http.HTTPFlow):
    return http.HTTPRequest(
        first_line_format="origin_form",  # ???
        scheme=flow.request.scheme,
        port=flow.request.port,
        path=flow.request.path,
        http_version=flow.request.http_version,
        content=flow.request.content,
        host=flow.request.host,
        headers=flow.request.headers,
        method=flow.request.method,
    )

# uses REGEX to find a JWT token in the cookies
def get_jwt(cookies: dict):
    token = None
    for cookie in cookies.values():
        token = re.search(r'eyJ[\w\-_]+\.eyJ[\w\-_]+\.[\w\-_]*', cookie)
        if token is not None:
            break
    if token is None:
        return None
    else:
        return token.group(0)

# generates a none alg JWT token from a valid one (keeping the same payload and signature)
def generate_none_token_with_signature(token: str):
    header, payload, signature = token.split('.')
    header_decoded = base64.b64decode(header + '=' * (-len(header) % 4))
    parsed_header = json.loads(header_decoded)
    parsed_header['alg'] = 'None'
    header_encoded = base64.b64encode(json.dumps(parsed_header).encode()).decode().replace('=', '')
    return header_encoded + '.' + payload + '.' + signature

# drops the signature from a JWT token
def drop_token_signature(token: str):
    header, payload, signature = token.split('.')
    return header + '.' + payload + '.'

def is_request_in_scope(flow: http.HTTPFlow):
    return urlparse(flow.request.url).netloc == APP_SCOPE


# replays the request after checking it is not a replay (to avoid an infinite loop)
def replay_flow(flow: http.HTTPFlow):
    
    flow.request.ignore = True  # marks the request as a replay request
        
    # print(f'><> Replaying request: {flow.request}')

    # replays the specified flow (request cycle)
    playback_action = ctx.master.addons.get('clientplayback')
    playback_action.start_replay([flow])


def print_attack_success(attack_name, flow: http.HTTPFlow):
    print('--' * 25)
    print('FOUND',attack_name, 'in', flow.request.path)
    print('--' * 25, '\n')