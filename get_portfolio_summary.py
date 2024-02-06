import sys
import requests
import argparse
import json
import time

# Global variables
base_url = None
tenant_name = None
auth_url = None
iam_base_url = None
auth_token = None
debug = False

def generate_auth_url():
    global iam_base_url
        
    try:
        if debug:
            print("Generating authentication URL...")
        
        if iam_base_url is None:
            iam_base_url = base_url.replace("ast.checkmarx.net", "iam.checkmarx.net")
            if debug:
                print(f"Generated IAM base URL: {iam_base_url}")
        
        temp_auth_url = f"{iam_base_url}/auth/realms/{tenant_name}/protocol/openid-connect/token"
        
        if debug:
            print(f"Generated authentication URL: {temp_auth_url}")
        
        return temp_auth_url
    except AttributeError:
        print("Error: Invalid base_url provided")
        sys.exit(1)

def authenticate(api_key):
    if auth_url is None:
        return None
    
    if debug:
        print("Authenticating with API...")
        
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {api_key}'
    }
    data = {
        'grant_type': 'refresh_token',
        'client_id': 'ast-app',
        'refresh_token': api_key
    }
    
    try:
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status()
        
        json_response = response.json()
        access_token = json_response.get('access_token')
        
        if not access_token:
            print("Error: Access token not found in the response.")
            return None
        
        if debug:
            print("Successfully authenticated")
        
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during authentication: {e}")
        sys.exit(1)

def create_report():
    if debug:
        print("Creating report...")
        
    headers = {
        "Content-Type": "application/json; version=1.0",
        "Accept": "application/json",
        'Authorization': f'Bearer {auth_token}'
    }
    data = {
        "reportName": "project-list",
        "reportType": "ui",
        "fileFormat": "csv",
        "data": {
            "projectId": "",
        }
    }
    
    try:
        response = requests.post(f"{base_url}/api/reports/", headers=headers, json=data)
        response.raise_for_status()
        
        report_response = response.json()
        report_id = report_response.get('reportId')

        if debug:
            print(f"Report creation initiated successfully: {report_id}")

        return report_id
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during report creation: {e}")
        print(response)
        sys.exit(1)

def download_report(report_id, filename):
    if debug:
        print(f"Downloading report {report_id}...")
    
    headers = {
        'Authorization': f'Bearer {auth_token}',
        'Accept': 'application/octet-stream',
    }
    
    try:
        response = requests.get(f"{base_url}/api/reports/{report_id}/download", headers=headers, stream=True)
        response.raise_for_status()

        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        if debug:
            print(f"Report downloaded successfully: {filename}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during report download: {e}")
        sys.exit(1)

def main():
    global base_url
    global tenant_name
    global debug
    global auth_url
    global auth_token
    global iam_base_url

    # Parse and handle various CLI flags
    parser = argparse.ArgumentParser(description='Export a CxOne scan workflow as a CSV file')
    parser.add_argument('--base_url', required=True, help='Region Base URL')
    parser.add_argument('--iam_base_url', required=False, help='Region IAM Base URL')
    parser.add_argument('--tenant_name', required=True, help='Tenant name')
    parser.add_argument('--api_key', required=True, help='API key for authentication')
    parser.add_argument('--output', required=True, help='Output filename for the downloaded report')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()
    
    base_url = args.base_url
    tenant_name = args.tenant_name
    debug = args.debug
            
    if args.iam_base_url:
        iam_base_url = args.iam_base_url
    
    auth_url = generate_auth_url()
    auth_token = authenticate(args.api_key)
    
    if auth_token is None:
        return

    report_id = create_report()

    try:
        headers = {
            "Content-Type": "application/json; version=1.0",
            "Accept": "application/json",
            'Authorization': f'Bearer {auth_token}'
        }
            
        while True:
            response = requests.get(f"{base_url}/api/reports/{report_id}", headers=headers)
            response.raise_for_status()

            status_response = response.json()
            status = status_response.get('status')

            if status in ['requested', 'started']:
                if debug:
                    print(f"Report status: {status}. Checking again in 5 seconds...")
                time.sleep(5)
            elif status == 'failed':
                print("Report generation failed.")
                sys.exit(1)
            elif status == 'completed':
                if debug:
                    print("Report generation completed.")
                break  # Exit the loop
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while checking the report status: {e}")
        sys.exit(1)

    download_report(report_id, args.output)



if __name__ == "__main__":
    main()