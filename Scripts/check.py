import json

with open("reports/storage.json") as f:
    sa = json.load(f)

with open("reports/blob.json") as f:
    blob = json.load(f)

def check(name, condition):
    print(f"{name}: {'PASS' if condition else 'FAIL'}")

print("=== CIS CHECK ===")

check("HTTPS Only", sa.get("enableHttpsTrafficOnly") == True)

check("TLS >= 1.2", sa.get("minimumTlsVersion") == "TLS1_2")

check("No Public Access", sa.get("allowBlobPublicAccess") == False)

check("Public Network Disabled", sa.get("publicNetworkAccess") == "Disabled")

check("Blob Soft Delete", blob["deleteRetentionPolicy"]["enabled"] == True)

check("Container Soft Delete", blob["containerDeleteRetentionPolicy"]["enabled"] == True)