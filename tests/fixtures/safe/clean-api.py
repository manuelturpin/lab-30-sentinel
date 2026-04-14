# SAFE: Properly secured Python API patterns
# These should NOT trigger detection patterns

import json
import os
from pathlib import Path
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

# SAFE: URL allowlisting — not SSRF
ALLOWED_URLS = ['https://api.internal.com', 'https://cdn.safe.com']

@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    if url not in ALLOWED_URLS:
        return jsonify(error='URL not allowed'), 403
    import requests
    response = requests.get(url, timeout=5)
    return response.text

# SAFE: JSON serialization instead of pickle
@app.route('/api/load-session', methods=['POST'])
def load_session():
    data = json.loads(request.data)
    return jsonify(data)

# SAFE: yaml.safe_load (not yaml.load)
import yaml
@app.route('/api/parse-config', methods=['POST'])
def parse_config():
    config = yaml.safe_load(request.data)
    return jsonify(config)

# SAFE: Path traversal prevented
UPLOAD_DIR = Path('/data/uploads').resolve()

@app.route('/api/read-file')
def read_file():
    filename = request.args.get('path', '')
    filepath = (UPLOAD_DIR / filename).resolve()
    if not str(filepath).startswith(str(UPLOAD_DIR)):
        return jsonify(error='Access denied'), 403
    return filepath.read_text()

# SAFE: No eval — using ast.literal_eval for safe parsing
import ast
@app.route('/api/compute', methods=['POST'])
def compute():
    expr = request.json.get('expression')
    result = ast.literal_eval(expr)
    return jsonify(result=result)

# SAFE: subprocess without shell=True
import subprocess
@app.route('/api/health')
def health():
    result = subprocess.run(['df', '-h'], capture_output=True, text=True)
    return result.stdout

# SAFE: Authentication decorator present
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not verify_token(token):
            return jsonify(error='Unauthorized'), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/admin/config', methods=['PUT'])
@require_auth
def update_config():
    new_config = request.json
    save_config(new_config)
    return jsonify(status='updated')

# SAFE: Privilege check before grant
@app.route('/api/grant-role', methods=['POST'])
@require_auth
def grant_role():
    if not current_user.is_superadmin:
        return jsonify(error='Forbidden'), 403
    user_id = request.json['user_id']
    role = request.json['role']
    if role not in ALLOWED_ROLES:
        return jsonify(error='Invalid role'), 400
    db.execute('UPDATE users SET role = %s WHERE id = %s', (role, user_id))
    return jsonify(granted=True)
