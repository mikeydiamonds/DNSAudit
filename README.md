# DNSAudit
`DNSAudit.sh` fetches a list of compromised domains from Zonefiles.io, and loops through each domain to check its resolution against various secure DNS providers.

## Description

`DNSAudit` is a comprehensive DNS provider audit tool designed to test how different DNS providers resolve domains. Inspired by Tom Lawrence's 2023 Best DNS for Secure Browsing [video](https://youtu.be/NUT4K3tk9Ns?si=qz_Lq9gwUbuBjx2n) and [code](https://forums.lawrencesystems.com/t/which-is-the-best-dns-for-secure-browsing-cloudflare-quad9-nextdns-and-adguard-dns-youtube-release/18910/2) and combined with previous private efforts from myself, this script focuses on the indicators of various DNS providers when encountering potentially harmful or compromised domains.

## Features

- Fetches a list of compromised domains for testing.
- Filters for `.com` and `.net` domains.
- Tests domain resolution across various DNS providers.
- Provides real-time, visually engaging feedback in the terminal.
- Outputs results to CSV files for further analysis.

## Usage

This script is meant to test network deployments only and will not work on roaming agents.

1. Clone the repository: `git clone https://github.com/mikeydiamonds/DNSAudit.git`
2. Navigate to the directory: `cd DNSAudit.sh`
3. Make the script executable: `chmod +x DNSAudit.sh`
4. Run the script: `./DNSAudit.sh`

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Disclaimer

This code and its contents are solely my own work in combination with [code provided by Tom Lawrence](https://forums.lawrencesystems.com/t/which-is-the-best-dns-for-secure-browsing-cloudflare-quad9-nextdns-and-adguard-dns-youtube-release/18910/2) and do not reflect the views, strategies, or opinions of my employer or any other entity. Use this script at your own discretion and responsibility.

## License

[MIT](https://choosealicense.com/licenses/mit/)

