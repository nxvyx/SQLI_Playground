import time
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .sqli_detector import SQLiDetector
import json
from datetime import datetime

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, detector, log_file):
        self.detector = detector
        self.log_file = log_file
        self.last_position = 0
        
        # Initialize last_position to current file size
        try:
            self.last_position = Path(log_file).stat().st_size
        except FileNotFoundError:
            self.last_position = 0
    
    def on_modified(self, event):
        if event.src_path.endswith(self.log_file):
            self.check_new_entries()
    
    def check_new_entries(self):
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                # Move to the last read position
                f.seek(self.last_position)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update the last position
                self.last_position = f.tell()
                
                if new_lines:
                    self.process_entries(new_lines)
        except FileNotFoundError:
            print(f"Log file not found: {self.log_file}")
        except Exception as e:
            print(f"Error reading log file: {e}")
    
    def process_entries(self, entries):
        findings = self.detector.detect_in_logs(entries)
        for finding in findings:
            self.handle_finding(finding)
    
    def handle_finding(self, finding):
        # Log the finding to a separate file
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'sqli_detected',
            'severity': finding['severity'],
            'ip': finding['ip'],
            'matched_patterns': finding['matched_patterns'],
            'log_entry': finding
        }
        
        # Print to console with color based on severity
        if finding['severity'] == 'high':
            color_code = '\033[91m'  # Red
        elif finding['severity'] == 'medium':
            color_code = '\033[93m'  # Yellow
        else:
            color_code = '\033[94m'   # Blue
        
        print(f"{color_code}[{finding['severity'].upper()}] SQL Injection attempt detected from {finding['ip']}")
        print(f"Matched patterns: {', '.join(finding['matched_patterns'])}")
        print(f"Log entry: {finding['data']}\033[0m")  # Reset color
        
        # Save to attack attempts log
        self.detector.log_attack_attempt(
            ip=finding['ip'],
            attack_type='sqli_attempt',
            details={
                'matched_patterns': finding['matched_patterns'],
                'log_entry': finding
            }
        )

class SQLiMonitor:
    def __init__(self, log_dir='logs', log_file='security.log'):
        self.log_dir = log_dir
        self.log_file = log_file
        self.detector = SQLiDetector(log_file=str(Path(log_dir) / log_file))
        self.observer = Observer()
        
        # Ensure log directory exists
        Path(log_dir).mkdir(exist_ok=True)
        
        # Initialize log file if it doesn't exist
        log_path = Path(log_dir) / log_file
        if not log_path.exists():
            log_path.touch()
    
    def start(self):
        print(f"Starting SQLi monitor. Watching {self.log_dir}/{self.log_file}")
        print("Press Ctrl+C to stop monitoring...\n")
        
        event_handler = LogFileHandler(
            detector=self.detector,
            log_file=str(Path(self.log_dir) / self.log_file)
        )
        
        # Start with an initial check of the log file
        event_handler.check_new_entries()
        
        # Set up the observer to watch for changes
        self.observer.schedule(
            event_handler,
            path=self.log_dir,
            recursive=False
        )
        self.observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        print("\nStopping SQLi monitor...")
        self.observer.stop()
        self.observer.join()
        print("SQLi monitor stopped.")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitor logs for SQL injection attempts')
    parser.add_argument('--log-dir', default='logs', help='Directory containing log files')
    parser.add_argument('--log-file', default='security.log', help='Log file to monitor')
    
    args = parser.parse_args()
    
    monitor = SQLiMonitor(
        log_dir=args.log_dir,
        log_file=args.log_file
    )
    
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
