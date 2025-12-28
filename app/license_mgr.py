import jwt
import datetime
import os

# In production, load this from a file embedded in the Docker image
PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxrU9Js/bel0NZc9Fq1XS
QysdBj1+xyzmDeB74l8t/pQ5sN9+1F231P+IoF9AP0bMPY3JbaGhQMBGlFPjfza9
+5Vm1onUzapxqO7JtBH6WwkTUQJDXxIh6XwOMkvFz+wxEsdmJFeLcGKn6dKusOmK
UQEUPFzJBMUA6Cw1q1VLq1seRsiJnZLhAJUNp8mgVBSL6oHCbzRNJHoSKUnhtj/m
mIfOmvhG6CFiK391MqQ/FCESv1OcX7DGhuXvD/w5Fr7bpuLWRQ+dDNIAiDoXbdof
nS4vBjZai4rxNo/CGt+4d5UH7QbCgUJfdWWwl6MxtLUwOpkptWnZNbJfsrOgUS2f
GQIDAQAB
-----END PUBLIC KEY-----
"""

def verify_license():
    """
    Verifies /app/data/license.lic.
    Returns: (bool, message)
    """
    license_path = "/app/data/license.lic"
    
    if not os.path.exists(license_path):
        return False, "License file missing. Please mount license.lic to /app/data/"
    
    try:
        with open(license_path, 'r') as f:
            token = f.read().strip()
            
        # Verify signature and expiration
        # payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"]) # Uncomment for real RSA
        
        # MOCK for this demo (Remove in Prod)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        exp = datetime.datetime.fromtimestamp(payload['exp'])
        if exp < datetime.datetime.now():
            return False, f"License expired on {exp}"
            
        return True, f"Licensed to: {payload.get('client')}"
        
    except Exception as e:
        return False, f"Invalid License: {str(e)}"