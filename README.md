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

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
