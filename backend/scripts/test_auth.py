
import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential

load_dotenv()

client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")
tenant_id = os.getenv("AZURE_TENANT_ID")

print(f"Testing Auth for Tenant: {tenant_id}")
try:
    cred = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
    token = cred.get_token("https://api.loganalytics.io/.default")
    print("SUCCESS: Token acquired!")
except Exception as e:
    print(f"FAILURE: {e}")
