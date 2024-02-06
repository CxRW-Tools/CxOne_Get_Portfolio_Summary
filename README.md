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
python get_portfolio_summary.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY  --output OUTPUT_FILENAME [--debug]
```

### Arguments

- `--base_url`: The base URL for the Checkmarx One API.
- `--tenant_name`: Your Checkmarx One tenant name.
- `--api_key`: API key for authentication.
- `--email`: Email address to send the report to.
- `--output`: The filename where the report will be saved.
- `--debug`: (Optional) Enable detailed debug output.

## Example

Here is an example command to run the script:

```bash
python get_portfolio_summary.py --base_url https://ast.checkmarx.net --tenant_name myTenant --api_key 12345abcde --email example@example.com --output report.csv --debug
```

This command will authenticate with Checkmarx One, create a report, monitor its status until completion, and download it as `report.csv`.
