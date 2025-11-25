import re
import time
import json
import sqlite3
from datetime import datetime
from urllib.parse import urlparse, parse_qs

class SQLiDetector:
    def __init__(self, log_file='logs/security.log', db_path='vuln_app.db'):
        self.log_file = log_file
        self.db_path = db_path
        self.patterns = [
            # SQL Comment patterns
            r'--\s',
            r'#',
            r'/\*.*?\*/',
            
            # SQL Keywords
            r'\b(UNION\s+ALL|UNION\s+SELECT|SELECT\s+.*\bFROM\b|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b',
            r"\b(OR\s+['\"])",
            r"\b(AND\s+['\"])",
            r'\b(EXEC\s*\(|EXEC\s+SP_|EXEC\s+XP_)',
            
            # Tautologies
            r"\b(OR\s+['\"\d]+\s*=\s*['\"\d]+\s*--?|OR\s+['\"\d]+\s*=\s*['\"\d]+\s*$)",
            r"\b(OR\s+['\"][^']*['\"]\s*=\s*['\"][^']*['\"],?\s*--?|OR\s+['\"][^']*['\"]\s*=\s*['\"][^']*['\"],?\s*$)",
            
            # Time-based patterns
            r"\b(WAITFOR\s+DELAY\s+['\"]?\d+:[\d\.]+['\"]?|SLEEP\s*\(\s*\d+\s*\))",
            
            # Error-based patterns
            r'\b(CAST\s*\(|CONVERT\s*\(|IF\s*\(|BENCHMARK\s*\()',
            
            # System functions
            r'\b(DB_NAME\s*\(|USER\s*\(|SYSTEM_USER\s*\(|SESSION_USER\s*\()',
            
            # Stacked queries
            r';\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|RENAME|GRANT|REVOKE|COMMIT|ROLLBACK|SAVEPOINT)',
            
            # Generic SQLi patterns
            r'\b(1=1|1=0|2>1|'')',
            r'\b(OR\s+[\w\d]+\s*[=<>!]+\s*[\w\d]+)',
            r'\b(AND\s+[\w\d]+\s*[=<>!]+\s*[\w\d]+)'
        ]
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]
        
    def detect_in_logs(self, log_entries=None):
        """Analyze logs for SQL injection attempts"""
        if log_entries is None:
            try:
                with open(self.log_file, 'r') as f:
                    log_entries = f.readlines()
            except FileNotFoundError:
                return []
        
        suspicious_entries = []
        
        for entry in log_entries:
            if not entry.strip():
                continue
                
            try:
                # Parse log entry
                parts = entry.strip().split(' - ', 3)
                if len(parts) < 4:
                    continue
                    
                timestamp = ' - '.join(parts[:2])
                ip = parts[2]
                log_type = parts[3].split(' - ', 1)[0]
                data = parts[3].split(' - ', 1)[1] if ' - ' in parts[3] else ""
                
                # Check for SQLi patterns
                is_sqli = False
                matched_patterns = []
                
                for pattern in self.compiled_patterns:
                    if pattern.search(data):
                        is_sqli = True
                        matched_patterns.append(pattern.pattern)
                
                if is_sqli:
                    suspicious_entries.append({
                        'timestamp': timestamp,
                        'ip': ip,
                        'type': log_type,
                        'data': data,
                        'matched_patterns': matched_patterns,
                        'severity': self._calculate_severity(matched_patterns)
                    })
                    
            except Exception as e:
                print(f"Error processing log entry: {e}")
                continue
                
        return suspicious_entries
    
    def _calculate_severity(self, matched_patterns):
        """Calculate severity based on matched patterns"""
        high_severity = [
            r'UNION\s+SELECT',
            r'EXEC\s*\(|EXEC\s+SP_|EXEC\s+XP_',
            r'WAITFOR\s+DELAY',
            r'SLEEP\s*\('
        ]
        
        medium_severity = [
            r'OR\s+.*?=.*?',
            r'1=1',
            r'--\s',
            r'/\*.*?\*/'
        ]
        
        for pattern in high_severity:
            if any(re.search(pattern, p, re.IGNORECASE) for p in matched_patterns):
                return 'high'
                
        for pattern in medium_severity:
            if any(re.search(pattern, p, re.IGNORECASE) for p in matched_patterns):
                return 'medium'
                
        return 'low'
    
    def analyze_http_request(self, request_data):
        """Analyze HTTP request data for SQL injection attempts"""
        findings = []
        
        # Check URL parameters
        if 'url' in request_data:
            parsed_url = urlparse(request_data['url'])
            query_params = parse_qs(parsed_url.query)
            
            for param, values in query_params.items():
                for value in values:
                    result = self._check_string(value)
                    if result['is_sqli']:
                        findings.append({
                            'type': 'url_parameter',
                            'parameter': param,
                            'value': value,
                            'severity': result['severity'],
                            'matched_patterns': result['matched_patterns']
                        })
        
        # Check POST data
        if 'data' in request_data and isinstance(request_data['data'], dict):
            for key, value in request_data['data'].items():
                if isinstance(value, str):
                    result = self._check_string(value)
                    if result['is_sqli']:
                        findings.append({
                            'type': 'form_data',
                            'field': key,
                            'value': value,
                            'severity': result['severity'],
                            'matched_patterns': result['matched_patterns']
                        })
        
        # Check headers
        if 'headers' in request_data and isinstance(request_data['headers'], dict):
            for header, value in request_data['headers'].items():
                if isinstance(value, str):
                    result = self._check_string(value)
                    if result['is_sqli']:
                        findings.append({
                            'type': 'header',
                            'header': header,
                            'value': value,
                            'severity': result['severity'],
                            'matched_patterns': result['matched_patterns']
                        })
        
        return findings
    
    def _check_string(self, input_str):
        """Check a single string for SQL injection patterns"""
        matched_patterns = []
        
        for pattern in self.compiled_patterns:
            if pattern.search(input_str):
                matched_patterns.append(pattern.pattern)
        
        return {
            'is_sqli': len(matched_patterns) > 0,
            'severity': self._calculate_severity(matched_patterns) if matched_patterns else None,
            'matched_patterns': matched_patterns
        }
    
    def log_attack_attempt(self, ip, attack_type, details):
        """Log detected attack attempts to a separate file"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'type': attack_type,
            'details': details
        }
        
        with open('logs/attack_attempts.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def generate_report(self, findings):
        """Generate a human-readable report of findings"""
        if not findings:
            return "No SQL injection attempts detected."
        
        report = ["SQL Injection Detection Report"]
        report.append("=" * 80)
        report.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total findings: {len(findings)}")
        report.append("-" * 80)
        
        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Sort by severity (high to low)
        for severity in ['high', 'medium', 'low', 'unknown']:
            if severity in by_severity:
                report.append(f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])} findings):")
                for i, finding in enumerate(by_severity[severity], 1):
                    report.append(f"\n{i}. Type: {finding.get('type', 'unknown')}")
                    if 'parameter' in finding:
                        report.append(f"   Parameter: {finding['parameter']}")
                    if 'field' in finding:
                        report.append(f"   Field: {finding['field']}")
                    if 'header' in finding:
                        report.append(f"   Header: {finding['header']}")
                    report.append(f"   Value: {finding.get('value', 'N/A')}")
                    report.append(f"   Matched patterns: {', '.join(finding.get('matched_patterns', []))}")
        
        return '\n'.join(report)

# Example usage
if __name__ == "__main__":
    detector = SQLiDetector()
    
    # Example 1: Analyze logs
    print("Analyzing logs...")
    findings = detector.detect_in_logs()
    print(f"Found {len(findings)} potential SQL injection attempts.")
    
    # Example 2: Analyze a sample HTTP request
    sample_request = {
        'url': 'http://example.com/search?q=test%27%20OR%201%3D1--',
        'data': {
            'username': "admin'--",
            'password': 'password'
        },
        'headers': {
            'User-Agent': 'Mozilla/5.0',
            'X-Forwarded-For': '192.168.1.1'
        }
    }
    
    print("\nAnalyzing sample HTTP request...")
    findings = detector.analyze_http_request(sample_request)
    print(detector.generate_report(findings))
