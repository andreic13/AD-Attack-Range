import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def write_new_config(data):
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=2)
