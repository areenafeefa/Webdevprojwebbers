import subprocess
import re
import os
import sys

def kill_process_on_port(port):
    print(f"Finding process on port {port}...")
    try:
        # Run netstat to find PID
        # netstat -ano
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        
        pids = set()
        for line in lines:
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                pid = parts[-1]
                pids.add(pid)
                print(f"Found Listening Process: PID={pid}")
                
        if not pids:
            print(f"No process found listening on port {port}")
            return

        for pid in pids:
            print(f"DTOKILL: Killing PID {pid}...")
            # forceful kill
            subprocess.run(['taskkill', '/F', '/PID', pid])
            print(f"Killed PID {pid}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    kill_process_on_port(5001)
