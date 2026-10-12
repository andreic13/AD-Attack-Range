import os
import re # regex for replacing {{param_name}} in commands
import yaml

ATTACKS_DIR = os.path.join(os.path.dirname(__file__), "attacks")

def get_all_attacks_list():
    attacks = []
    for filename in sorted(os.listdir(ATTACKS_DIR)):
        if filename.endswith(".yml"):
            with open(os.path.join(ATTACKS_DIR, filename), "r") as f:
                attack = yaml.safe_load(f)
                attacks.append(attack)
    return attacks

def get_attack_by_id(attack_id):
    for attack in get_all_attacks_list():
        if attack["id"] == attack_id:
            return attack
    return None

def render_params_for_command(command, params):
    # replace {{param_name}} with the actual value provided by the user
    def replacer(match):
        key = match.group(1)
        return params.get(key, match.group(0))
    return re.sub(r"\{\{(\w+)\}\}", replacer, command)
