# CTF Utilities

This repository contains a collection of utility scripts for Capture The Flag (CTF) competitions and similar cybersecurity events. These tools are designed to assist in various aspects of CTF management, analysis, and data processing.

## Scripts

### 1. ip-scan.py

This script analyzes IP address usage across different teams, identifies shared IPs between teams, and provides ISP information for each IP address. It's designed to help detect potential collaboration or account sharing between teams in a competition.

#### Features

- Load and process tracking data, user data, and team data from CSV files
- Identify IP addresses shared between different teams
- Filter out Cloudflare and other ignored IP ranges
- Retrieve ISP information for each shared IP address
- Display results in a formatted table in the console
- Export results to a CSV file

#### Usage

1. Prepare your input CSV files:
   - `tracking.csv`: Contains IP tracking data
   - `users.csv`: Contains user information
   - `teams.csv`: Contains team information

2. Run the script:
   ```
   python ip-scan.py
   ```

3. The script will display the results in the console and export them to `shared_ips_results.csv`.

For more detailed information about ip-scan.py, including input file formats and output structure, please see the [ip-scan.py documentation](docs/ip-scan.md).

## Prerequisites

- Python 3.6+
- pip (Python package installer)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/degun-osint/CTFdUtils
   cd CTFdUtils
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

## Contributing

Contributions are welcome! If you have ideas for new scripts or improvements to existing ones, please feel free to submit a Pull Request or open an Issue.

## Acknowledgments

- [IP-API](https://ip-api.com/) for providing ISP information in ip-scan.py
- [PrettyTable](https://github.com/jazzband/prettytable) for console table formatting in ip-scan.py

## Future Scripts

We plan to add more utility scripts to this repository in the future. Stay tuned for updates!