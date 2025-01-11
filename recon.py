#!/usr/bin/env python3
import os
import sys
import json
import socket
import subprocess
import requests
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class ReconScanner:
    def __init__(self, target_ip):
        """Initialize scanner with target IP"""
        self.target_ip = target_ip
        self.results = {
            'timestamp': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'target_ip': target_ip,
            'nmap_results': {
                'ports': [],
                'os_info': {},
                'services': {},
                'scripts': {},
                'vulners': {}
            },
            'vulnerabilities': [],
            'device_type': 'unknown',
            'exploit_recommendations': []
        }
        
        # Disable SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Initialize results directory
        self.results_dir = 'scan_results'
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def run_nmap_scan(self):
        """Run comprehensive nmap scan"""
        print(f"[+] Starting comprehensive nmap scan on {self.target_ip}")
        
        # Basic port scan with service detection
        print("[*] Running initial service detection scan...")
        basic_scan = subprocess.run([
            'nmap', '-sS', '-sV', '-sC', '-p-',
            '--min-rate', '1000',
            '--version-intensity', '5',
            '-T4', self.target_ip,
            '-oX', 'nmap_basic.xml'
        ], capture_output=True, text=True)
        
        if basic_scan.returncode == 0:
            print("[+] Basic scan complete")
            self._parse_nmap_output(basic_scan.stdout)
        
        # OS detection scan
        print("[*] Running OS detection scan...")
        os_scan = subprocess.run([
            'nmap', '-sS', '-O', '--osscan-guess',
            '-T4', self.target_ip,
            '-oX', 'nmap_os.xml'
        ], capture_output=True, text=True)
        
        if os_scan.returncode == 0:
            print("[+] OS detection complete")
            self._parse_nmap_output(os_scan.stdout, scan_type='os')
        
        # UDP scan for key services
        print("[*] Running UDP service scan...")
        udp_ports = "53,67,68,69,123,161,162,500,514,520,1900,5353"
        udp_scan = subprocess.run([
            'nmap', '-sU', '-sV', '--version-intensity', '5',
            '-p', udp_ports, '-T4', self.target_ip,
            '-oX', 'nmap_udp.xml'
        ], capture_output=True, text=True)
        
        if udp_scan.returncode == 0:
            print("[+] UDP scan complete")
            self._parse_nmap_output(udp_scan.stdout, scan_type='udp')
        
        # Vulnerability scanning with NSE scripts
        if self.results['nmap_results']['ports']:
            print("[*] Running vulnerability detection scripts...")
            ports = ','.join(map(str, self.results['nmap_results']['ports']))
            vuln_scan = subprocess.run([
                'nmap', '-sV', '-p', ports,
                '--script', 'vuln,exploit,auth,default,discovery,version',
                '-T4', self.target_ip,
                '-oX', 'nmap_vuln.xml'
            ], capture_output=True, text=True)
            
            if vuln_scan.returncode == 0:
                print("[+] Vulnerability scan complete")
                self._parse_nmap_output(vuln_scan.stdout, scan_type='vuln')
        
        # Additional service-specific scans based on found ports
        self._run_service_specific_scans()
    
    def _run_service_specific_scans(self):
        """Run targeted scans based on discovered services"""
        services = self.results['nmap_results']['services']
        
        for port, service_info in services.items():
            service = service_info.get('name', '').lower()
            
            if service in ['http', 'https']:
                print(f"[*] Running detailed HTTP scan on port {port}...")
                http_scan = subprocess.run([
                    'nmap', '-p', str(port),
                    '--script', 'http-enum,http-headers,http-methods,http-auth,http-title,http-robots.txt',
                    self.target_ip,
                    '-oX', f'nmap_http_{port}.xml'
                ], capture_output=True, text=True)
                
                if http_scan.returncode == 0:
                    self._parse_nmap_output(http_scan.stdout, scan_type='http')
            
            elif service == 'ssh':
                print(f"[*] Running SSH security scan on port {port}...")
                ssh_scan = subprocess.run([
                    'nmap', '-p', str(port),
                    '--script', 'ssh2-enum-algos,ssh-auth-methods',
                    self.target_ip,
                    '-oX', f'nmap_ssh_{port}.xml'
                ], capture_output=True, text=True)
                
                if ssh_scan.returncode == 0:
                    self._parse_nmap_output(ssh_scan.stdout, scan_type='ssh')
            
            elif service == 'snmp':
                print(f"[*] Running SNMP enumeration on port {port}...")
                snmp_scan = subprocess.run([
                    'nmap', '-p', str(port), '-sU',
                    '--script', 'snmp-info,snmp-interfaces,snmp-sysdescr',
                    self.target_ip,
                    '-oX', f'nmap_snmp_{port}.xml'
                ], capture_output=True, text=True)
                
                if snmp_scan.returncode == 0:
                    self._parse_nmap_output(snmp_scan.stdout, scan_type='snmp')
    
    def _parse_nmap_output(self, output, scan_type='basic'):
        """Parse nmap output and update results"""
        # Extract port information
        port_lines = re.finditer(r'(\d+)\/(\w+)\s+(\w+)\s+(.+)', output)
        for match in port_lines:
            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            
            if port not in self.results['nmap_results']['ports']:
                self.results['nmap_results']['ports'].append(port)
            
            self.results['nmap_results']['services'][port] = {
                'protocol': protocol,
                'state': state,
                'name': service
            }
        
        # Extract OS information
        if scan_type == 'os':
            os_match = re.search(r'OS details: (.+)', output)
            if os_match:
                self.results['nmap_results']['os_info']['details'] = os_match.group(1)
        
        # Extract script output
        script_lines = re.finditer(r'\|\s*([^:]+):\s*\n\|\s*(.+)', output)
        for match in script_lines:
            script_name = match.group(1)
            script_output = match.group(2)
            
            if script_name not in self.results['nmap_results']['scripts']:
                self.results['nmap_results']['scripts'][script_name] = []
            self.results['nmap_results']['scripts'][script_name].append(script_output)
    
    def analyze_vulnerabilities(self):
        """Analyze scan results for vulnerabilities"""
        print("[*] Analyzing vulnerabilities...")
        
        for script_name, outputs in self.results['nmap_results']['scripts'].items():
            if any(vuln_term in script_name.lower() for vuln_term in ['vuln', 'exploit', 'weak', 'default']):
                for output in outputs:
                    self.results['vulnerabilities'].append({
                        'type': script_name,
                        'details': output
                    })
        
        # Service-specific vulnerability checks
        for port, service_info in self.results['nmap_results']['services'].items():
            service = service_info.get('name', '').lower()
            version = service_info.get('version', '')
            
            if service in ['http', 'https']:
                if 'scripts' in self.results['nmap_results']:
                    headers = self.results['nmap_results']['scripts'].get('http-headers', [])
                    if headers:
                        self._analyze_http_security(port, headers)
            
            elif service == 'ssh' and version:
                self._analyze_ssh_security(port, version)
    
    def _analyze_http_security(self, port, headers):
        """Analyze HTTP security headers"""
        security_headers = {
            'X-Frame-Options': False,
            'X-XSS-Protection': False,
            'X-Content-Type-Options': False,
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False
        }
        
        for header in headers:
            header_name = header.split(':')[0].strip()
            if header_name in security_headers:
                security_headers[header_name] = True
        
        missing_headers = [h for h, present in security_headers.items() if not present]
        if missing_headers:
            self.results['vulnerabilities'].append({
                'type': 'missing_security_headers',
                'port': port,
                'details': f"Missing security headers: {', '.join(missing_headers)}"
            })
    
    def _analyze_ssh_security(self, port, version):
        """Analyze SSH version security"""
        version_num = re.search(r'(\d+\.?\d*)', version)
        if version_num:
            ver = float(version_num.group(1))
            if ver < 7.0:
                self.results['vulnerabilities'].append({
                    'type': 'outdated_ssh',
                    'port': port,
                    'details': f"SSH version {version} is outdated and may contain vulnerabilities"
                })
    
    def generate_exploit_recommendations(self):
        """Generate exploit recommendations based on findings"""
        print("[*] Generating exploit recommendations...")
        
        for vuln in self.results['vulnerabilities']:
            vuln_type = vuln['type'].lower()
            
            if 'http' in vuln_type:
                self.results['exploit_recommendations'].append({
                    'name': 'web_exploit.py',
                    'description': 'Exploit web vulnerabilities using discovered misconfigurations',
                    'target': f"http://{self.target_ip}:{vuln.get('port', 80)}"
                })
            
            elif 'ssh' in vuln_type:
                self.results['exploit_recommendations'].append({
                    'name': 'ssh_exploit.py',
                    'description': 'Exploit SSH vulnerabilities using version-specific attacks',
                    'target': f"ssh://{self.target_ip}:{vuln.get('port', 22)}"
                })
            
            elif 'snmp' in vuln_type:
                self.results['exploit_recommendations'].append({
                    'name': 'snmp_exploit.py',
                    'description': 'Exploit SNMP misconfigurations and default credentials',
                    'target': f"snmp://{self.target_ip}:{vuln.get('port', 161)}"
                })
    
    def run_recon(self):
        """Run all reconnaissance steps"""
        print(f"[+] Starting reconnaissance on {self.target_ip}")
        self.run_nmap_scan()
        self.analyze_vulnerabilities()
        self.generate_exploit_recommendations()
        print("[+] Reconnaissance complete")
        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python recon.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    recon = ReconScanner(target_ip)
    results = recon.run_recon()
    
    # Save results
    filename = f"recon_results_{results['timestamp']}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Results saved to {filename}")
    
    # Print summary
    print("\nDevice Information:")
    print(f"Type: {results['device_type']}")
    
    print("\nOpen Ports:")
    for port in results['nmap_results']['ports']:
        service = results['nmap_results']['services'].get(port, {})
        print(f"- {port}/{service.get('protocol', 'unknown')}: {service.get('name', 'unknown')}")
    
    print("\nVulnerabilities:")
    for vuln in results['vulnerabilities']:
        print(f"- {vuln['type']}: {vuln['details']}")
    
    print("\nRecommended Exploits:")
    for exploit in results['exploit_recommendations']:
        print(f"- {exploit['name']}: {exploit['description']}")
        print(f"  Target: {exploit['target']}")

if __name__ == "__main__":
    main()
