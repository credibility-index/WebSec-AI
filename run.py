#!/usr/bin/env python3
"""Start WebSecAI Streamlit app. Usage: python run.py  or  python3 run.py"""
import os
import subprocess
import sys

def main():
    app_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(app_dir)
    cmd = [sys.executable, "-m", "streamlit", "run", "app.py", "--server.headless", "true"]
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
