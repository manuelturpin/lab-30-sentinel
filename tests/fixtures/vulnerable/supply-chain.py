# INTENTIONALLY VULNERABLE — Sentinel rule-tester fixtures
# DO NOT use in production. Every pattern here is a known vulnerability.
# CWE-502, CWE-22, CWE-94, CWE-829, CWE-506

import pickle
import yaml
import os
import zipfile
import tarfile

# CWE-502: Pickle deserialization from untrusted source
def load_model(model_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    return model

# CWE-502: YAML load without SafeLoader
def parse_pipeline_config(config_str):
    config = yaml.load(config_str)
    return config

# CWE-502: jsonpickle (unsafe by default)
import jsonpickle
def deserialize_task(data):
    return jsonpickle.decode(data)

# CWE-22: Zip slip — extracting without path validation
def extract_package(zip_path, dest_dir):
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)

# CWE-22: Tar slip
def extract_tarball(tar_path, dest_dir):
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest_dir)

# CWE-94: Dynamic import from user-specified module
def load_plugin(plugin_name):
    module = __import__(plugin_name)
    return module.run()

# CWE-94: urllib.request.urlopen with user URL
def fetch_remote(url):
    import urllib.request
    data = urllib.request.urlopen(url).read()
    return data

# CWE-829: Loading from untrusted CDN without SRI
SCRIPT_TAG = '<script src="http://cdn.example.com/lib.js"></script>'

# CWE-502: shelve (uses pickle internally)
import shelve
def load_cache():
    db = shelve.open('cache.db')
    data = db['user_prefs']
    return data
