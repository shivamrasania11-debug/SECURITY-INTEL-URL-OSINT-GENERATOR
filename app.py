"""
Root Launcher for Security Analysis & URL Intelligence Generator.
Allows running 'python app.py' directly from the root workspace directory.
"""
import os
import sys
import runpy

app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_url_intel")
os.chdir(app_dir)
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

if __name__ == "__main__":
    target_app_py = os.path.join(app_dir, "app.py")
    runpy.run_path(target_app_py, run_name="__main__")

