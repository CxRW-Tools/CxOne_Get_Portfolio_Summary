# Get Portfolio Summary Usage Guide

## Summary

This tool automates the process of creating and downloading a summary report of all projects from Checkmarx One. Specifically, it provides a CSV file with the following fields:

- Project ID
- Project Name
- Created At
- Origin
- Project Tags
- Groups
- Assigned To Applications
- Last Scan Date
- Project Risk Level
- Total Vulnerabilities
- Critical Vulnerabilities
- High Vulnerabilities
- Medium Vulnerabilities
- Low Vulnerabilities

## Usage

Execute the script with the required parameters to create and download a report:

```bash
python get_portfolio_summary.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY  --output OUTPUT_FILENAME [--build] [--debug]
```

### Arguments

- `--base_url`: The base URL of the Checkmarx One region.
- `--tenant_name`: Your Checkmarx One tenant name.
- `--api_key`: API key for authentication.
- `--output`: The filename where the report will be saved.
- `--build`: (Optional) Use an alternative approach and build the CSV piece by piece; this is to be used if the number of projects is large and causing a failure of the primary approach
- `--debug`: (Optional) Enable detailed debug output.

## Example

Here is an example command to run the script:

```bash
python get_portfolio_summary.py --base_url https://ast.checkmarx.net --tenant_name myTenant --api_key 12345abcde --output report.csv --debug
```

This command will authenticate with Checkmarx One, create a report, monitor its status until completion, and download it as `report.csv`.
