import json
from pathlib import Path

config_dir = Path.home() / ".securegenomics"
config_file = config_dir / "config.json"

# Ensure directory exists
config_dir.mkdir(exist_ok=True)

# Update or create config
config = {}
if config_file.exists():
    with open(config_file, 'r') as f:
        config = json.load(f)

# Update github_org to your GitHub username
config["github_org"] = "securegenomics" 

with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)

print(f"Updated config to use GitHub org: securegenomics")
print(f"Config saved to: {config_file}")
