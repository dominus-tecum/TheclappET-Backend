#!/usr/bin/env python3
"""
Simple Admin Creation Script - No Database Required
"""

import requests

RENDER_APP_URL = "https://theclappet-backend.onrender.com"

def create_admin():
    print("\n" + "="*50)
    print("        CREATE ADMIN")
    print("="*50)
    
    email = input("  Email [admin@theclapp.com]: ").strip() or "admin@theclapp.com"
    password = input("  Password [Admin123!]: ").strip() or "Admin123!"
    username = input("  Username [admin]: ").strip() or "admin"
    name = input("  Name [System Administrator]: ").strip() or "System Administrator"
    
    # Any non-empty token works with your current backend
    payload = {
        "email": email,
        "password": password,
        "username": username,
        "name": name,
        "one_time_token": "simple-token-123"
    }
    
    try:
        response = requests.post(f"{RENDER_APP_URL}/api/admin/create", json=payload)
        
        if response.status_code == 201:
            result = response.json()
            print("\n" + "="*50)
            print("✅ ADMIN CREATED SUCCESSFULLY!")
            print("="*50)
            print(f"   Admin ID: {result['admin_id']}")
            print(f"   Email: {result['email']}")
            print("="*50)
        else:
            print("\n❌ Failed to create admin")
            print(f"   Error: {response.json().get('detail', 'Unknown error')}")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    input("\nPress Enter to continue...")

if __name__ == "__main__":
    create_admin()