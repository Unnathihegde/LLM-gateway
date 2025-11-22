import subprocess
import sys
import time


def main():
    python = sys.executable

    # Start backend
    backend_proc = subprocess.Popen(
        [python, "-m", "uvicorn", "backend:app", "--reload"]
    )
    time.sleep(3)

    # Start frontend
    frontend_proc = subprocess.Popen(
        [python, "-m", "streamlit", "run", "frontend.py"]
    )

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        backend_proc.terminate()
        frontend_proc.terminate()


if __name__ == "__main__":
    main()
