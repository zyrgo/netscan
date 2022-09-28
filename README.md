# NetScan

## _Automated ASN and CIDR scanning tool_

NetScan is a shell script which automates the scanning the CIDRs in the ASN, Port scanning the CIDR blocks for alive hosts and cves.

## Features:

- Scan CIDR associated with an ASN number
- Port scan top 100 ports via Masscan
- Finding out possible CVEs associated with any IPs via Shodan
- Screenshoting alive hosts via gowitness

## Installation

NetScan requires [masscan](https://github.com/robertdavidgraham/masscan) for port scanning, [gowitness](https://github.com/sensepost/gowitness) for screenshoting.

_Install the dependencies if not already installed:_

```sh
sudo apt-get install masscan
go install github.com/sensepost/gowitness@latest
```
_Clone the repository and run netscan:_
```sh
git clone https://github.com/zyrgo/netscan.git
cd netscan
sh netscan {-a|-c} <asn-number|cidr-number>
```
