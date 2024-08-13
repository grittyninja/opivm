import nmap
import re
import yaml
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urlunparse
from lib.utils import perform_http_request

class Engine:
    def __init__(self):
        self.yaml_file = 'lib/payloads.yml'
        self.payloads = self.load_payloads()
    
    def load_payloads(self):
        with open(self.yaml_file, 'r') as file:
            return yaml.safe_load(file)

    def _inject_payload(self, target, payload, signature, hhi=False):
        # handle host header injection
        if hhi:
            status_code, response_text = perform_http_request(http_request=target, hhi_payload=payload)
            if status_code != 0 and signature in response_text:
                return True, {'method': target['method'], 'url': target['url'], 'query_param': '?', 'payload': f"Host: {payload}"}
            return False, {}
        
        else:
            # Inject the payload into query parameters
            for key in target['query']:
                original_value = target['query'][key]
                target['query'][key] = payload
                status_code, response_text = perform_http_request(target)
                target['query'][key] = original_value
                if status_code != 0 and signature in response_text:
                    return True, {'method': target['method'], 'url': target['url'], 'query_param': key, 'payload': payload}

            # Inject the payload into JSON body parameters
            if target['json_body']:
                for key in target['json_body']:
                    original_value = target['json_body'][key]
                    target['json_body'][key] = payload
                    status_code, response_text = perform_http_request(target)
                    target['json_body'][key] = original_value
                    if status_code != 0 and signature in response_text:
                        return True, {"method": target['method'], 'url': target['url'], 'json_body_param': key, 'payload': payload}

            # Inject the payload into form body parameters
            if target['form_body']:
                for key in target['form_body']:
                    original_value = target['form_body'][key]
                    target['form_body'][key] = payload
                    status_code, response_text = perform_http_request(target)
                    target['form_body'][key] = original_value
                    if status_code != 0 and signature in response_text:
                        return True, {"method": target['method'], 'url': target['url'], "form_body_param": key, "payload": payload}
            return False, {}

    def detect_vulnerability(self, target, vuln_type):
        for payload, signature in zip(self.payloads[vuln_type]['payloads'], self.payloads[vuln_type]['signatures']):
            vuln, poc_payload = self._inject_payload(target, payload, signature, hhi=(vuln_type == 'hhi'))
            if vuln:
                return True, poc_payload
        return False, {}

    def detect_xss(self, target):
        return self.detect_vulnerability(target, 'xss')

    def detect_rfi(self, target):
        return self.detect_vulnerability(target, 'rfi')
    
    def detect_ssti(self, target):
        return self.detect_vulnerability(target, 'ssti')
    
    def detect_hhi(self, target):
        return self.detect_vulnerability(target, 'hhi')

    def detect_lfi(self, target):
        return self.detect_vulnerability(target, 'lfi')

    def detect_sqli(self, target):
        return self.detect_vulnerability(target, 'sqli')

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_nmap(self, target: str) -> Dict:
        parsed_url = urlparse(target)
        
        # Handle cases where the scheme is not provided
        if not parsed_url.scheme:
            parsed_url = urlparse(f"http://{target}")
        
        host = parsed_url.hostname
        port = parsed_url.port
        
        if not host:
            return {"error": f"Invalid target: {target}"}
        
        # Set default ports based on the scheme if not specified
        if not port:
            port = 443 if parsed_url.scheme == 'https' else 80
        
        try:
            print(f"Scanning {host}:{port}...")
            result = self.nm.scan(hosts=host, ports=str(port), arguments=f'-sV --script=vulners -O -Pn')
            return result
        except nmap.PortScannerError as e:
            return {"error": f"Nmap scan error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error during scan: {str(e)}"}

class VulnerabilityReport:
    def __init__(self, scan_result: Dict, vulnerability_results: Dict, targets: Dict):
        self.scan_result = scan_result
        self.vulnerability_results = vulnerability_results
        self.targets = targets
        self.vuln_id_counter = 1

    def _generate_vuln_id(self):
        current_date = datetime.now().strftime("%y%m%d")
        vuln_id = f"VULN-{current_date}-{self.vuln_id_counter:04d}"
        self.vuln_id_counter += 1
        return vuln_id

    def _get_parameter_type(self, result):
        if 'query_param' in result:
            return f"`{result['query_param']}` <br> Query"
        elif 'json_body_param' in result:
            return f"`{result['json_body_param']}` <br> JSON Body"
        elif 'form_body_param' in result:
            return f"`{result['form_body_param']}` <br> Form Body"
        else:
            return "N/A"

    def _find_cve(self, vulners_output: str) -> List[str]:
        cve_pattern = r'(CVE-\d{4}-\d+)'
        link_template = 'https://vulners.com/cve/{cve}'
        results = []

        # Find all matches in the vulners_output
        cve_matches = re.findall(cve_pattern, vulners_output)
        
        for cve in set(cve_matches):  
            link = link_template.format(cve=cve)
            results.append(f"{cve} ({link})")
        
        return results

    def generate_markdown(self) -> str:
        markdown = "# OPIVM - Vulnerability Report\n\n"
        current_date = datetime.now().strftime("%d-%m-%Y %H:%M")
        markdown += f"**Date:** {current_date}\n"
        api_targets = self.targets
        
        # Generate list for Host Scopes
        markdown += "\n## Host Scopes:\n\n"
        hosts = []
        for target in api_targets:
            url = target.get('url','')
            if url != '':
                p = urlparse(url)
                host = f"{p.hostname}:{p.port or (443 if p.scheme == 'https' else 80)}"
                if host not in hosts:
                    markdown += f"- {host}\n"
                    hosts.append(host)
        
        
        # Generate Table for API Scopes
        markdown += "\n## API Scopes:\n\n"
    
        markdown += "|No | Method | URL | Query Params | Body Params |\n"
        markdown += "|--|--|--|--|--|\n"
        
        for i, item in enumerate(api_targets, start=1):
            if 'url' not in item:
                continue
            
            method = item.get('method', 'N/A').upper()
            url = item['url']
            
            query_params = ', '.join(item.get('query', {}).keys())
            query_params = query_params if query_params else 'None'
            
            body_params = []
            if item.get('json_body'):
                body_params.append(f"{', '.join(item['json_body'].keys())} <br> type: JSON")
            if item.get('form_body'):
                body_params.append(f"{', '.join(item['form_body'].keys())} <br> type: Form")
            body_params = ' | '.join(body_params) if body_params else 'None'
            markdown += f"| {i} | {method} | {url} | {query_params} | {body_params} |\n"

        if not self.scan_result:
            return markdown + "No scan results available. The scan may have failed to run or returned no data.\n"

        markdown += "\n## Infrastructures Vulnerabilities\n\n"
        for target, target_data in self.scan_result.items():
            markdown += f"\n### Target: {target}\n\n"
            
            if 'error' in target_data:
                markdown += f"Error: {target_data['error']}\n\n"
                continue

            if 'scan' not in target_data:
                markdown += "No scan data available for this target.\n\n"
                continue

            for host, host_data in target_data['scan'].items():
                markdown += f"**Host:** {host}\n\n"
                
                # Add OS information
                if 'osmatch' in host_data:
                    os_matches = host_data['osmatch']
                    if os_matches:
                        best_match = os_matches[0]  # Get the best match
                        os_name = best_match.get('name', 'Unknown')
                        os_accuracy = best_match.get('accuracy', 'N/A')
                        markdown += f"**OS:** {os_name} (Accuracy: {os_accuracy}%)\n\n"
                    else:
                        markdown += "**OS:** Could not determine OS\n\n"
                else:
                    markdown += "**OS:** OS detection was not performed or failed\n\n"
                
                if 'tcp' not in host_data:
                    markdown += "No open TCP ports found.\n\n"
                    continue

                for port, port_data in host_data['tcp'].items():
                    markdown += f"**Port:** {port} ({port_data.get('name', 'unknown')})\n\n"
                    markdown += f"- State: {port_data.get('state', 'unknown')}\n"
                    service_name = f"{port_data.get('product', 'unknown')} {port_data.get('version', '')}"
                    if service_name.strip() == "":
                        server_header_raw = port_data.get('script', {}).get('fingerprint-strings', '')
                        service_name = re.search(r'(?i)server:\s*(.+?)(?:\r?\n|\Z)', server_header_raw)
                        service_name = service_name.group(1) if service_name else ''
                    
                    markdown += f"- Service: {service_name}\n\n"
                
                    if 'script' in port_data and 'vulners' in port_data['script']:
                        vulnerabilities = self._find_cve(port_data['script']['vulners'])

                        if vulnerabilities:
                            markdown += "**Vulnerabilities:**\n\n"
                            for vuln in vulnerabilities:
                                markdown += f"  - References: {vuln}\n"
                        else:
                            markdown += "*No vulnerabilities found.*\n\n"
                    else:
                            markdown += "*No vulnerabilities found.*\n\n"

        # Application-level Vulnerabilities Table
        markdown += "\n## Application Vulnerabilities\n\n"
        markdown += "| ID | Vulnerability | URL | Method | Parameter | Payload |\n"
        markdown += "|--|--|--|--|--|--|\n"

        for vuln_type, results in self.vulnerability_results.items():
            for result in results:
                vuln_id = self._generate_vuln_id()
                parameter = self._get_parameter_type(result)
                markdown += f"| {vuln_id} | {vuln_type.upper()} | {result['url']} | {result['method']} | {parameter} | ```{result['payload']}``` |\n"

        return markdown

class NetworkScanner:
    def __init__(self):
        self.scanner = NmapScanner()
        self.engine = Engine()

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))

    def scan(self, targets: List[Dict]) -> str:
        unique_hosts = set()
        valid_targets = []

        for target in targets:
            if 'url' in target:
                base_url = self._get_base_url(target['url'])
                unique_hosts.add(base_url)
                valid_targets.append(target)

        nmap_results = {}
        for host in unique_hosts:
            print(f"Starting Nmap scan for {host}")
            result = self.scanner.scan_nmap(host)
            print(f"Nmap scan result for {host}") 
            nmap_results[host] = result

        print("[+] Nmap scans completed. Starting vulnerability detection...")
        vulnerability_results = {
            'xss': [],
            'rfi': [],
            'lfi': [],
            'sqli': [],
            'ssti': [],
            'hhi': []
        }

        for target in valid_targets:
            for vuln_type in ['xss', 'rfi', 'lfi', 'sqli', 'ssti', 'hhi']:
                print(f"[+] Scanning {vuln_type.upper()} on {target['url']} ...")
                detect_method = getattr(self.engine, f'detect_{vuln_type}')
                is_vulnerable, details = detect_method(target)
                if is_vulnerable:
                    vulnerability_results[vuln_type].append(details)

        print("[+] Vulnerability detection completed. Generating report...")
        report = VulnerabilityReport(nmap_results, vulnerability_results, targets)
        return report.generate_markdown()