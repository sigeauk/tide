#!/usr/bin/env python3
"""
Repository Health Check Script
"""

import os
import json
import sys

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def check_file(path: str, description: str, min_size_kb: int = 10) -> bool:
    if not os.path.exists(path):
        print(f"{RED}✗ MISSING:{RESET} {description}")
        print(f"  Expected at: {path}")
        return False
    
    size_kb = os.path.getsize(path) / 1024
    if size_kb < min_size_kb:
        print(f"{YELLOW}⚠ WARNING:{RESET} {description} seems too small ({size_kb:.1f} KB)")
        return False
    
    print(f"{GREEN}✓ OK:{RESET} {description} ({size_kb:.1f} KB)")
    return True

def main():
    print("\n" + "=" * 60)
    print("TIDE Repository Health Check")
    print("=" * 60 + "\n")
    
    all_ok = True
    
    print("MITRE ATT&CK Data:")
    print("-" * 40)
    
    mitre_files = [
        ("/opt/repos/mitre/enterprise-attack.json", "Enterprise ATT&CK", 5000),
        ("/opt/repos/mitre/mobile-attack.json", "Mobile ATT&CK", 1000),
        ("/opt/repos/mitre/ics-attack.json", "ICS ATT&CK", 500),
        ("/opt/repos/mitre/pre-attack.json", "Pre-ATT&CK", 100),
    ]
    
    for path, desc, min_size in mitre_files:
        if not check_file(path, desc, min_size):
            all_ok = False
    
    print("\n" + "=" * 60)
    if all_ok:
        print(f"{GREEN}✓ All repositories present{RESET}")
    else:
        print(f"{RED}✗ Some repositories missing{RESET}")
    print("=" * 60 + "\n")
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
