#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from datetime import datetime
import xml.etree.ElementTree as ET

class NmapScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results_dir = f'nmap_results_{self.timestamp}'
        self.results = {
            'timestamp': self.timestamp,
            'target_ip': target_ip,
            'scan_results': {}
        }
        
        # Create results directory
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

    def run_comprehensive_scan(self):
        """Run all possible nmap scans"""
        scan_types = {
            'intense_scan': ['-T4', '-A', '-v'],
            'intense_scan_plus_udp': ['-sS', '-sU', '-T4', '-A', '-v'],
            'intense_scan_all_tcp': ['-p', '1-65535', '-T4', '-A', '-v'],
            'intense_scan_no_ping': ['-T4', '-A', '-v', '-Pn'],
            'ping_scan': ['-sn'],
            'quick_scan': ['-T4', '-F'],
            'quick_scan_plus': ['-sV', '-T4', '-O', '-F', '--version-light'],
            'quick_traceroute': ['-sn', '--traceroute'],
            'regular_scan': ['-sS', '-sV'],
            'slow_comprehensive': ['-sS', '-sU', '-T2', '-A', '-v', '--version-all'],
            
            # Additional thorough scans
            'full_vulnerability_scan': ['-sV', '--script', 'vuln,exploit,auth,default,discovery,version'],
            'all_nse_scripts': ['-sV', '--script', 'all'],
            'safe_scripts': ['-sV', '--script', 'safe'],
            'default_scripts': ['-sV', '--script', 'default'],
            'service_detection': ['-sV', '--version-intensity', '9'],
            'os_detection': ['-O', '--osscan-guess'],
            'timing_template': ['-T5'],
            
            # UDP specific scans
            'udp_scan': ['-sU', '--top-ports', '1000'],
            'udp_service_scan': ['-sU', '-sV', '--version-intensity', '9', '--top-ports', '1000'],
            
            # TCP specific scans
            'tcp_connect_scan': ['-sT'],
            'tcp_syn_scan': ['-sS'],
            'tcp_ack_scan': ['-sA'],
            'tcp_window_scan': ['-sW'],
            'tcp_maimon_scan': ['-sM'],
            
            # Specific script categories
            'auth_scripts': ['-sV', '--script', 'auth'],
            'broadcast_scripts': ['-sV', '--script', 'broadcast'],
            'brute_scripts': ['-sV', '--script', 'brute'],
            'discovery_scripts': ['-sV', '--script', 'discovery'],
            'dos_scripts': ['-sV', '--script', 'dos'],
            'exploit_scripts': ['-sV', '--script', 'exploit'],
            'external_scripts': ['-sV', '--script', 'external'],
            'fuzzer_scripts': ['-sV', '--script', 'fuzzer'],
            'intrusive_scripts': ['-sV', '--script', 'intrusive'],
            'malware_scripts': ['-sV', '--script', 'malware'],
            'version_scripts': ['-sV', '--script', 'version'],
            'vuln_scripts': ['-sV', '--script', 'vuln']
        }

        for scan_name, scan_args in scan_types.items():
            print(f"\n[+] Running {scan_name}...")
            output_file = os.path.join(self.results_dir, f'{scan_name}')
            
            # Run scan with both XML and normal output
            cmd = ['nmap'] + scan_args + [
                '-oA', output_file,  # Save in all formats (normal, XML, grepable)
                self.target_ip
            ]
            
            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=7200  # 2 hour timeout per scan
                )
                
                # Save raw results
                self.results['scan_results'][scan_name] = {
                    'command': ' '.join(cmd),
                    'stdout': process.stdout,
                    'stderr': process.stderr,
                    'return_code': process.returncode,
                    'output_files': {
                        'normal': f'{output_file}.nmap',
                        'xml': f'{output_file}.xml',
                        'grepable': f'{output_file}.gnmap'
                    }
                }
                
                # Parse XML output if available
                xml_file = f'{output_file}.xml'
                if os.path.exists(xml_file):
                    try:
                        self.parse_xml_output(xml_file, scan_name)
                    except Exception as e:
                        print(f"Error parsing XML for {scan_name}: {str(e)}")
                
                print(f"[+] {scan_name} completed. Results saved.")
                
            except subprocess.TimeoutExpired:
                print(f"[-] {scan_name} timed out after 2 hours")
                self.results['scan_results'][scan_name] = {
                    'command': ' '.join(cmd),
                    'error': 'Scan timed out after 2 hours'
                }
            except Exception as e:
                print(f"[-] Error in {scan_name}: {str(e)}")
                self.results['scan_results'][scan_name] = {
                    'command': ' '.join(cmd),
                    'error': str(e)
                }

    def parse_xml_output(self, xml_file, scan_name):
        """Parse nmap XML output for structured data"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            parsed_data = {
                'hosts': [],
                'ports': [],
                'os_matches': [],
                'scripts': []
            }
            
            # Parse host information
            for host in root.findall('.//host'):
                host_data = {
                    'status': host.find('status').get('state'),
                    'addresses': []
                }
                
                # Get all addresses (IPv4, IPv6, MAC)
                for addr in host.findall('address'):
                    host_data['addresses'].append({
                        'type': addr.get('addrtype'),
                        'addr': addr.get('addr'),
                        'vendor': addr.get('vendor', '')
                    })
                
                # Get hostname information
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    host_data['hostnames'] = [
                        {
                            'name': hostname.get('name'),
                            'type': hostname.get('type')
                        }
                        for hostname in hostnames.findall('hostname')
                    ]
                
                parsed_data['hosts'].append(host_data)
                
                # Parse ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_data = {
                            'protocol': port.get('protocol'),
                            'portid': port.get('portid'),
                            'state': port.find('state').get('state'),
                            'service': {}
                        }
                        
                        # Get service information
                        service = port.find('service')
                        if service is not None:
                            for attr in service.attrib:
                                port_data['service'][attr] = service.get(attr)
                        
                        # Get script output
                        scripts = port.findall('script')
                        if scripts:
                            port_data['scripts'] = []
                            for script in scripts:
                                script_data = {
                                    'id': script.get('id'),
                                    'output': script.get('output')
                                }
                                port_data['scripts'].append(script_data)
                                parsed_data['scripts'].append(script_data)
                        
                        parsed_data['ports'].append(port_data)
                
                # Parse OS detection
                os = host.find('os')
                if os is not None:
                    for osmatch in os.findall('osmatch'):
                        os_data = {
                            'name': osmatch.get('name'),
                            'accuracy': osmatch.get('accuracy'),
                            'line': osmatch.get('line')
                        }
                        parsed_data['os_matches'].append(os_data)
            
            self.results['scan_results'][scan_name]['parsed_data'] = parsed_data
            
        except Exception as e:
            print(f"Error parsing XML file {xml_file}: {str(e)}")
            self.results['scan_results'][scan_name]['parsed_data'] = {
                'error': f"Failed to parse XML: {str(e)}"
            }

    def save_results(self):
        """Save final results to JSON file"""
        output_file = os.path.join(self.results_dir, 'complete_results.json')
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[+] Complete results saved to {output_file}")
        
        # Create a summary file
        summary_file = os.path.join(self.results_dir, 'scan_summary.txt')
        with open(summary_file, 'w') as f:
            f.write(f"Nmap Scan Summary for {self.target_ip}\n")
            f.write(f"Timestamp: {self.timestamp}\n\n")
            
            for scan_name, scan_data in self.results['scan_results'].items():
                f.write(f"\n=== {scan_name} ===\n")
                if 'error' in scan_data:
                    f.write(f"Error: {scan_data['error']}\n")
                    continue
                
                if 'parsed_data' in scan_data:
                    pd = scan_data['parsed_data']
                    
                    # Write host information
                    f.write("\nHosts Found:\n")
                    for host in pd['hosts']:
                        f.write(f"  Status: {host['status']}\n")
                        for addr in host['addresses']:
                            f.write(f"  Address: {addr['addr']} ({addr['type']})\n")
                    
                    # Write port information
                    f.write("\nOpen Ports:\n")
                    for port in pd['ports']:
                        if port['state'] == 'open':
                            f.write(f"  {port['portid']}/{port['protocol']}")
                            if 'service' in port and 'name' in port['service']:
                                f.write(f" - {port['service']['name']}")
                            f.write("\n")
                    
                    # Write OS detection results
                    if pd['os_matches']:
                        f.write("\nOS Detection:\n")
                        for os in pd['os_matches']:
                            f.write(f"  {os['name']} (Accuracy: {os['accuracy']})\n")
                    
                    # Write script output
                    if pd['scripts']:
                        f.write("\nScript Results:\n")
                        for script in pd['scripts']:
                            f.write(f"  {script['id']}:\n")
                            f.write(f"    {script['output']}\n")
                
                f.write("\n" + "="*50 + "\n")
        
        print(f"[+] Scan summary saved to {summary_file}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python recon.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    scanner = NmapScanner(target_ip)
    scanner.run_comprehensive_scan()
    scanner.save_results()

if __name__ == "__main__":
    main()

