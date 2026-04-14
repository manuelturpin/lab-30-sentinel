# INTENTIONALLY VULNERABLE — Sentinel rule-tester fixtures
# DO NOT use in production. Every pattern here is a known vulnerability.
# CWE-918, CWE-502, CWE-22, CWE-284, CWE-269, CWE-94, CWE-306

import pickle
import yaml
import os
import subprocess
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# CWE-918: SSRF — requests.get with user-controlled URL
@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    response = requests.get(url)
    return response.text

# CWE-918: SSRF via requests.post
@app.route('/api/webhook', methods=['POST'])
def send_webhook():
    response = requests.post(request.json['callback_url'], json=request.json['payload'])
    return jsonify(status=response.status_code)

# CWE-502: Unsafe deserialization — pickle
@app.route('/api/load-session', methods=['POST'])
def load_session():
    data = pickle.loads(request.data)
    return jsonify(data)

# CWE-502: Unsafe deserialization — yaml.load without SafeLoader
@app.route('/api/parse-config', methods=['POST'])
def parse_config():
    config = yaml.load(request.data)
    return jsonify(config)

# CWE-502: Unsafe deserialization — marshal
import marshal
@app.route('/api/exec-code', methods=['POST'])
def exec_code():
    code = marshal.loads(request.data)
    return 'OK'

# CWE-22: Path traversal
@app.route('/api/read-file')
def read_file():
    filename = request.args.get('path')
    filepath = os.path.join('/data', filename)
    with open(filepath) as f:
        return f.read()

# CWE-94: Code injection via eval
@app.route('/api/compute', methods=['POST'])
def compute():
    expr = request.json.get('expression')
    result = eval(expr)
    return jsonify(result=result)

# CWE-94: subprocess with shell=True
@app.route('/api/run', methods=['POST'])
def run_command():
    cmd = request.json.get('command')
    output = subprocess.check_output(cmd, shell=True)
    return output

# CWE-284: No authorization check
@app.route('/api/admin/config', methods=['PUT'])
def update_config():
    new_config = request.json
    save_config(new_config)
    return jsonify(status='updated')

# CWE-269: Privilege management — no check before grant
@app.route('/api/grant-admin', methods=['POST'])
def grant_admin():
    user_id = request.json['user_id']
    db.execute('UPDATE users SET role = %s WHERE id = %s', ('admin', user_id))
    return jsonify(granted=True)

# CWE-306: No authentication on sensitive endpoint
@app.route('/api/export-data')
def export_data():
    data = db.query('SELECT * FROM sensitive_data')
    return jsonify(data)
