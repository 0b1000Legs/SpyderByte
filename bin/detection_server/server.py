from flask import Flask, jsonify, request, make_response
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

REPORTS_ACCESS_TOKEN = 'b43c9fe7a5c16adfbf0027f6bded4f0b0df47632c0eacfb7d72301c27124a288'
successful_attack_ids = []
reported_attacks = set()

def run_detection_server(host, port):
    app = Flask(__name__)
    
    @app.route('/get_reports', methods=['GET'])
    def get_reports():
        access_token = request.args.get('access_token')
        pulse_request_id = request.args.get('pulse_request_id')
        
        if not pulse_request_id or not access_token or access_token != REPORTS_ACCESS_TOKEN:
            return ('', 403)

        if not len(successful_attack_ids):
            return jsonify([])
        
        response = make_response(jsonify(successful_attack_ids))
        reported_attacks.union(set(successful_attack_ids))
        successful_attack_ids.clear()
        response.headers['Pulse-Request-Id'] = pulse_request_id
        return response


    @app.route('/report_ssrf/<ssrf_attack_id>', methods=['GET', 'POST', 'PUT', 'DELETE'])
    def log_attack_request(ssrf_attack_id):
        if not ssrf_attack_id or ssrf_attack_id in reported_attacks:
            return ('', 200)
        successful_attack_ids.append(ssrf_attack_id)
        return ('', 200)


    app.run(host=host, port=port)
