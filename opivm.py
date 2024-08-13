import sys
import json
from lib.utils import perform_http_request, get_apis
from lib.engine import NetworkScanner
from lib.report import Report

def main():
    print("== OPIVM : OpenAPI Vulnerability Mitigation ==\n")

    # to check whether api works or not based on http_code 
    http_code_default = 200
    if len(sys.argv) != 2:
        print("Usage: python opivm.py <path_to_swagger.yml>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    http_requests = get_apis(file_path)
    for http_request in http_requests:
        status_code, response_text = perform_http_request(http_request)
        print(f"> Checking API [{http_request['method'].upper()}] {http_request['url']} -> ",end='')
        if status_code != http_code_default:
            print("Failed!")
            print("> There is problem with api access, please fix your swagger file")
            sys.exit()
        else:
            print("OK!")

    print("\n[+] Start Network Scan ...\n")

    network_scanner = NetworkScanner()
    

    markdown_report = network_scanner.scan(http_requests)
    
    report = Report()
    report.markdown_to_pdf(markdown_report)
    report.send()

    print("\n[+] OPIVM Scan Completed!")

if __name__ == "__main__":
    main()
