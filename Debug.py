import json

# device = "VPN_Server"
device = "Merging_Unit"

file = open("DEBUG_device_cve_dict.json")
device_cve = json.load(file)

print(device_cve[device])
print(len(device_cve[device]))
print(f"For {device}")
