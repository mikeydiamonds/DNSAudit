# DNSAudit
`DNSAudit.sh` fetches a list of compromised domains from Zonefiles.io, and loops through each domain to check its resolution against various secure DNS providers.

## Description

`DNSAudit` is a comprehensive DNS provider audit tool designed to test how different DNS providers resolve domains. Inspired by Tom Lawrence's 2023 [DNS provider audit](https://youtu.be/NUT4K3tk9Ns?si=qz_Lq9gwUbuBjx2n) and enhanced by Mikey Pruitt, this script focuses on the indicators of various DNS providers when encountering potentially harmful or compromised domains.

## Features

- Fetches a list of compromised domains for testing.
- Filters for `.com` and `.net` domains.
- Tests domain resolution across various DNS providers.
- Provides real-time, visually engaging feedback in the terminal.
- Outputs results to CSV files for further analysis.

## Usage

1. Clone the repository:
