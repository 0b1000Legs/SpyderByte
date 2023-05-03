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


# replays the request after checking it is not a replay (to avoid an infinite loop)
def replay_flow(flow: http.HTTPFlow, request_marker):
    # if not flow.request.label == request_marker and hasattr(flow.request, 'ignore'):
    #     return

    flow.request.ignore = True  # marks the request as a replay request
        
    print(f'Replaying request: {flow.request}')

    # replays the specified flow (request cycle)
    playback_action = ctx.master.addons.get('clientplayback')
    playback_action.start_replay([flow])
