#!/usr/bin/env python3
import requests
from datetime import datetime

URL = "https://certificate.danielf.ch/api/health"

def main():
    try:
        resp = requests.get(URL, timeout=5)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"❌ Failed to fetch health: {e}")
        return

    print("\n📋 System Health Report")
    print("-" * 30)
    print(f"Status      : {data['status'].upper()}")
    print(f"Timestamp   : {data['timestamp']}")
    print(f"Uptime      : {data['uptime']} seconds\n")

    # Redis section
    redis = data.get("redis", {})
    print("🟢 Redis")
    print(f"   Status     : {redis.get('status','unknown').upper()}")
    print(f"   Connection : {redis.get('connection','unknown').capitalize()}\n")

    # Sessions section
    sessions = data.get("sessions", {})
    print("📊 Sessions")
    print(f"   Active Sessions            : {sessions.get('active_sessions',0)}")
    print(f"   Total Memory Used (MB)     : {sessions.get('total_memory_mb',0.0)}")
    print(f"   Oldest Session Age (hrs)   : {sessions.get('oldest_session_age_hours',0)}")
    print(f"   Newest Session Age (hrs)   : {sessions.get('newest_session_age_hours',0)}")
    print(f"   Total Requests             : {sessions.get('total_requests',0)}")
    print(f"   Avg. Requests per Session  : {sessions.get('average_requests_per_session',0.0)}")

if __name__ == "__main__":
    main()
