# main.py
import sys
import threading
from gui import run_app

def main():
    try:
        run_app()
    except Exception as e:
        print('Failed to run GUI:', e)
        sys.exit(1)

if __name__ == '__main__':
    main()
