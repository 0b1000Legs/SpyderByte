from mitmproxy import ctx, http
from helpers import RequestBuilder

class ReplayAgent:
    # sample add-on that replays the request after checking it is not a replay (to avoid an infinite loop)
    def request(self, flow: http.HTTPFlow):
        if hasattr(flow.request, 'replayed'):
            return
        
        print(f'Replaying request: {flow.request}')
        target_request = RequestBuilder.clone_request(flow)  # select the request builder needed, here we only clone it
        target_request.replayed = True  # marks the request as a replay request

        new_flow = flow.copy()
        new_flow.request = target_request

        # replays the specified flow (request cycle)
        playback_action = ctx.master.addons.get('clientplayback')
        playback_action.start_replay([new_flow])


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