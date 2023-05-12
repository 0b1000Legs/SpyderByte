import base64
import json
import re
from mitmproxy import ctx, http


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
        token = re.search(r'[\w\-_]+\.[\w\-_]+\.[\w\-_]+', cookie)
        if token is not None:
            break
    if token is None:
        return None
    else:
        return token.group(0)

# generates a faulty JWT token from a valid one
def generate_faulty_token(token: str):
    return token
    return token + 'a'
    header, payload, signature = token.split('.')
    payload_decoded = base64.b64decode(payload + '=' * (-len(payload) % 4))
    parsed_payload = json.loads(payload_decoded)
    parsed_payload['dummy'] = 'dummy'
    payload_encoded = base64.b64encode(json.dumps(parsed_payload).encode()).decode().replace('=', '')
    return header + '.' + payload_encoded + '.' + signature

# replays the request after checking it is not a replay (to avoid an infinite loop)
def replay_flow(flow: http.HTTPFlow):
    
    flow.request.ignore = True  # marks the request as a replay request
        
    print(f'Replaying request: {flow.request}')

    # replays the specified flow (request cycle)
    playback_action = ctx.master.addons.get('clientplayback')
    playback_action.start_replay([flow])
