from mitmproxy import http

class RequestBuilder:
    # returns a clone of the original request with no modifications, exists as a sample builder method
    def clone_request(self, flow: http.HTTPFlow):
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
