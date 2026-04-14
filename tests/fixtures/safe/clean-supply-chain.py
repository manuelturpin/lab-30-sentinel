# SAFE: Properly secured supply chain patterns
# These should NOT trigger detection patterns

import json
import os
import zipfile
import tarfile
from pathlib import Path

# SAFE: JSON serialization (safe alternative)
def load_model(model_path):
    with open(model_path, 'r') as f:
        model = json.load(f)
    return model

# SAFE: yaml.safe_load
import yaml
def parse_pipeline_config(config_str):
    config = yaml.safe_load(config_str)
    return config

# SAFE: Zip extraction with path validation
def extract_package(zip_path, dest_dir):
    dest = Path(dest_dir).resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            member_path = (dest / member).resolve()
            if not str(member_path).startswith(str(dest)):
                raise ValueError(f"Path traversal detected: {member}")
        zf.extractall(dest_dir)

# SAFE: Tar extraction with path validation
def extract_tarball(tar_path, dest_dir):
    dest = Path(dest_dir).resolve()
    with tarfile.open(tar_path) as tf:
        for member in tf.getmembers():
            member_path = (dest / member.name).resolve()
            if not str(member_path).startswith(str(dest)):
                raise ValueError(f"Path traversal detected: {member.name}")
        tf.extractall(dest_dir, filter='data')

# SAFE: Plugin loading from allowlist
ALLOWED_PLUGINS = {'auth', 'logging', 'metrics'}
def load_plugin(plugin_name):
    if plugin_name not in ALLOWED_PLUGINS:
        raise ValueError(f"Unknown plugin: {plugin_name}")
    module = __import__(f"plugins.{plugin_name}", fromlist=[plugin_name])
    return module.run()

# SAFE: SRI integrity on CDN scripts
SCRIPT_TAG = '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>'

# SAFE: Version read from file without exec
def get_version():
    with open('version.txt') as f:
        return f.read().strip()
