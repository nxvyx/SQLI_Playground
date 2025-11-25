# run.py
"""
SQL Injection Playground - Main Application Runner
"""

import sys
import os
from pathlib import Path

def setup_environment():
    """Set up the application environment"""
    # Create necessary directories
    Path('logs').mkdir(exist_ok=True)
    Path('static').mkdir(exist_ok=True)
    
    # Initialize database if needed
    try:
        from app.app import init_db
        print("[SETUP] Initializing database...")
        init_db()
        print("[OK] Database initialized successfully\n")
    except Exception as e:
        print(f"[WARN] Database initialization note: {e}\n")

def main():
    """Main entry point"""
    print("\n" + "="*60)
    print("   SQL Injection Playground with Detection Engine")
    print("="*60 + "\n")
    sys.stdout.flush()
    
    # Set up environment
    setup_environment()
    
    print("[INFO] Starting Flask Application (Port 5000)...\n")
    print("   Vulnerable App: http://localhost:5000")
    print("   Login: http://localhost:5000/login")
    print("   Search: http://localhost:5000/search")
    print("   Tutorials: http://localhost:5000/tutorials")
    print("   Logs: http://localhost:5000/logs\n")
    sys.stdout.flush()
    
    sys.path.insert(0, os.path.dirname(__file__))
    from app.app import app
    
    try:
        app.run(debug=True, port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\n[STOP] Shutting down...")
        print("Goodbye!\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()