import sys
import requests
import argparse
import json
import time
import csv

# Global variables
base_url = None
tenant_name = None
auth_url = None
iam_base_url = None
auth_token = None
debug = False
application_cache = {}
group_cache = {}

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

def get_projects():
    projects_data = []
    offset = 0
    total_count = 0

    if debug:
        print("Fetching project list...")

    headers = {
        "Content-Type": "application/json; version=1.0",
        "Accept": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }

    while True:
        try:
            response = requests.get(f"{base_url}/api/projects/",headers=headers,params={"offset": offset})
            response.raise_for_status()
            response_data = response.json()

            if offset == 0:
                total_count = response_data['totalCount']

            projects = response_data['projects']

            for project in projects:
                project_info = {
                    'id': project['id'],
                    'name': project['name'],
                    'createdAt': project['createdAt'],
                    'groups': project['groups'],
                    'tags': project['tags'],
                    'applicationIds': project['applicationIds']
                }
                projects_data.append(project_info)

            # Break the loop if we've retrieved all records
            if len(projects_data) >= total_count:
                break

            offset += len(projects)

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fetching the project list: {e}")
            sys.exit(1)

    if debug:
        print(f"Successfully fetched {len(projects_data)} projects.")

    return projects_data

def get_last_scan_data(projectId):
    if debug:
        print(f"Fetching last scan data for project ID: {projectId}")

    headers = {
        "Content-Type": "application/json; version=1.0",
        "Accept": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }

    try:
        response = requests.get(f"{base_url}/api/results-overview/projects?projectIds={projectId}",headers=headers)
        response.raise_for_status()

        scans = response.json()
        if not scans:
            print(f"No scan data found for project ID: {projectId}")
            return {}

        # Assuming the first item in the response is the relevant scan data for the project
        scan_data = scans[0]

        # Initialize the result dictionary with keys for all fields, applying default values as needed
        result = {
            "sourceOrigin": scan_data.get("sourceOrigin", "NO DATA FOUND"),  # Default to special string if not found
            "totalCounter": scan_data.get("totalCounter", 0),  # Default to 0
            "lastScanDate": scan_data.get("lastScanDate", "NO DATA FOUND"),  # Default to special string if not found
            "riskLevel": scan_data.get("riskLevel", "NO DATA FOUND"),  # Default to special string if not found
            "Critical": scan_data.get("Critical", 0),  # Default to 0
            "High": scan_data.get("High", 0),  # Default to 0
            "Medium": scan_data.get("Medium", 0),  # Default to 0
            "Low": scan_data.get("Low", 0),  # Default to 0
        }

        # Update the result dictionary with actual counts if present
        severity_counters = scan_data.get("severityCounters") or []
        for counter in severity_counters:
            severity = counter.get("severity")
            count = counter.get("counter", 0)
            if severity in result:
                result[severity] = count

        if debug:
            print(f"Last scan data for project ID {projectId}: {result}")

        return result
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching scan data for project ID {projectId}: {e}")
        return {}

def resolve_application_id(application_id):
    global application_cache
    
    if debug:
        print(f"Attempting to resolve application ID: {application_id}")
    
    # Check if the application_id is already in the cache
    if application_id in application_cache:
        if debug:
            print(f"Found application ID in cache: {application_id}")
        return application_cache[application_id]
    
    # Define the headers for the request
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    # Make the request to the API
    try:
        if debug:
            print(f"Fetching application name from API for ID: {application_id}")
        response = requests.get(f"{base_url}/api/applications/{application_id}", headers=headers)
        response.raise_for_status()
        application_data = response.json()

        # Extract the application name from the response and cache it
        application_name = application_data.get('name')
        if application_name:
            application_cache[application_id] = application_name
            if debug:
                print(f"Cached application name for ID {application_id}: {application_name}")
        else:
            if debug:
                print(f"No name found for application ID: {application_id}")
            application_name = "unresolvable application id"  # Default value if name is not in response
        
        return application_name

    except requests.exceptions.RequestException as e:
        if debug:
            print(f"An error occurred while fetching application name for ID {application_id}: {e}")
        return "unresolvable application id"

def resolve_group_id(group_id):
    global group_cache
    
    if debug:
        print(f"Attempting to resolve group ID: {group_id}")
    
    # Check if the grop_id is already in the cache
    if group_id in group_cache:
        if debug:
            print(f"Found group ID in cache: {group_id}")
        return group_cache[group_id]
    
    # Define the headers for the request
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "group/json",
        "Accept": "application/json",
    }
    
    # Make the request to the API
    try:
        if debug:
            print(f"Fetching group name from API for ID: {group_id}")
        response = requests.get(f"{iam_base_url}/auth/admin/realms/{tenant_name}/groups/{group_id}", headers=headers)
        response.raise_for_status()
        group_data = response.json()

        # Extract the group name from the response and cache it
        group_name = group_data.get('name')
        if group_name:
            group_cache[group_id] = group_name
            if debug:
                print(f"Cached group name for ID {group_id}: {group_name}")
        else:
            if debug:
                print(f"No name found for group ID: {group_id}")
            group_name = "unresolvable group id"  # Default value if name is not in response
        
        return group_name

    except requests.exceptions.RequestException as e:
        if debug:
            print(f"An error occurred while fetching group name for ID {group_id}: {e}")
        return "unresolvable group id"

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
    parser.add_argument('--output', required=True, help='Output filename for the downloaded CSV report')
    parser.add_argument('--build', action='store_true', help='Use an alternative approach and build the CSV piece by piece; this is to be used if the number of projects is large and causing a failure of the primary approach')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()
    
    base_url = args.base_url
    tenant_name = args.tenant_name
    build = args.build
    debug = args.debug
    csv_file_path = args.output
            
    if args.iam_base_url:
        iam_base_url = args.iam_base_url
    
    auth_url = generate_auth_url()
    auth_token = authenticate(args.api_key)

    if auth_token is None:
        return

    if not build: # the default approach
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

        download_report(report_id, csv_file_path)

    else: # Build the report from smaller, individual API calls
        # get the projects data
        projects_data = get_projects()
        project_counter = 0
        projects_count = len(projects_data)

        # get the scan-related data for each project
        for project in projects_data:
            project_counter += 1

            # inefficient but effective way to ensure the auth token doesn't expire: reauthenticate every 20 projects :-|
            if project_counter % 20 == 0:
                auth_token = authenticate(args.api_key)

            print(f"Processing data for project {project_counter}/{projects_count}")

            scan_data = get_last_scan_data(project['id'])
            # Append scan data to the project data
            project.update(scan_data)

            # Resolve the group names
            group_names = []

             # Loop through each group ID in the project's "groups" field
            for group_id in project.get('groups', []):
                # Resolve each group ID to a name
                group_name = resolve_group_id(group_id)
                # Add the resolved name to the list of group names for this project
                group_names.append(group_name)

            # Append the list of resolved group names to the project data
            project["groupNames"] = group_names

            # Resolve application names
            application_names = []
            
            # Loop through each application ID in the project's "applicationIds" field
            for application_id in project.get('applicationIds', []):
                # Resolve each application ID to a name
                application_name = resolve_application_id(application_id)
                # Add the resolved name to the list of application names for this project
                application_names.append(application_name)

            # Append the list of resolved application names to the project data
            project["applicationNames"] = application_names




        # output to the csv
        with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Project ID", "Project Name", "Created At", "Origin", "Project Tags", "Groups",
            "Assigned To Applications", "Last Scan Date", "Project Risk Level",
            "Total Vulnerabilities", "Critical Vulnerabilities", "High Vulnerabilities",
            "Medium Vulnerabilities", "Low Vulnerabilities"])

            # Iterate over the project data
            for project in projects_data:
        
                # Prepare the row data
                row = [
                    project["id"],
                    project["name"],
                    project["createdAt"],
                    project.get("sourceOrigin", ""),
                    ", ".join(sorted([f"{k}:{v}" for k, v in project.get("tags", {}).items()])),
                    ", ".join(sorted(project.get("groupNames", []))),
                    ", ".join(sorted(project.get("applicationNames", []))),
                    project["lastScanDate"],
                    project["riskLevel"],
                    project["totalCounter"],
                    project.get("Critical", 0),
                    project.get("High", 0),
                    project.get("Medium", 0),
                    project.get("Low", 0),
                ]

                # Write the project row to the CSV file
                writer.writerow(row)

        print(f"CSV file has been created at: {csv_file_path}")

if __name__ == "__main__":
    main()