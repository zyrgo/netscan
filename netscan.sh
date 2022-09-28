#!/bin/sh

red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
reset=$(tput sgr0)

# if [ "$(id -u)" -ne 0 ]; then
# printf "%s\n\n\t${red}please run this script as sudo\n\n${reset}"
# exit 0;
# fi
cidrScan() {
    printf "%s${yellow}Scanning alive ips in CIDR block:${red} $1 ${reset} \n"
    sudo masscan --range "$1" -p7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157 --rate 1000 --output-format json --output-filename scan-results.json

    printf "%s\n\t${yellow}Parsing alive ips and ports:${red} $1 ${reset} \n"
    sed <scan-results.json -e '/^\[/d' -e'/^\]/d' -e 's/,$//' | jq -r '[.ip, .ports[0].port] | @tsv' | sed 's/\t/:/' | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n  > alive-hosts

    # printf "%s\n\t${yellow}Looking for alive hosts via httpx: ${reset} \n"
    # httpx <alive-hosts -status-code -content-length -title -follow-redirects -threads 500 >> httpx-output 2>/dev/null

    # cut <httpx-output -d '[' -f1 | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n >> probed-hosts 2>&1

    printf "%s\n\t${yellow}Scanning probed ips for $1"
    ips=$(grep <alive-hosts -Eo "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | uniq)
    for i in $ips; do
        curl -s "https://internetdb.shodan.io/$i" > shodan.txt 2>&1
        #grep -Eio "CVE-([0-9]{1,4}[-])[0-9]{1,5}" shodan.txt >cve 2>&1
        jq ".vulns[]" shodan.txt | sed -E -e "s/\"//g" > cve 2>&1
        jq ".hostnames[]" shodan.txt | sed -E -e "s/\"//g" >> hostnames.txt 2>&1
        lines=$(wc <cve -l)
        if [ "$lines" -gt 0 ]; then
            printf "%s\n\n${i} maybe vulnerable to: \n\n$(grep <shodan.txt -Eio "CVE-([0-9]{1,4}[-])[0-9]{1,5}")\nSource: https://internetdb.shodan.io/$i" >> cves.txt 2>&1
        fi
        rm shodan.txt
        rm cve
    done
    vulns=$(cat cves.txt)
    printf "%s\n\n\t${yellow}Vulnerablities found by shodan:\n${vulns}${reset}"
    printf "%s ${yellow}Taking screenshots of the CIDR block ${reset} \n"
    gowitness file -f alive-hosts --threads 20 -P screenshots

}

asnScan() {
    printf "%s\n\t${yellow}Looking for CIDR in asn number:${red}$1${reset}\n"
    
    curl -s "https://api.bgpview.io/asn/$1/prefixes" | jq ".data.ipv4_prefixes[].parent.prefix" | sed -E -e "s/\"//g" | uniq | sort >ipv4prefixes

    curl -s "https://api.bgpview.io/asn/$1/prefixes" | jq ".data.ipv6_prefixes[].parent.prefix" | sed -E -e "s/\"//g" | uniq | sort >ipv6prefixes
    # grep <asn.txt -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9][0-9]" | tee "$1"cidr
    cidr=$(cat ipv4prefixes ipv6prefixes)
    for i in $cidr; do
        dir=$(echo "$i" | cut -d "/" -f1)
        mkdir -p "${dir}"
        cd "${dir}" || exit
        cidrScan "$i"
        cd ..
    done
}

while [ "$#" -gt 0 ]; do
    case "${1}" in
    -a | --asn)
        mkdir -p "$2"
        cd "$2" || exit
        asnScan "$2" && exit 0
        ;;
    -c | --cidr)
        dir=$(echo "$2" | cut -d "/" -f1)
        mkdir -p "${dir}"
        cd "${dir}" || exit
        cidrScan "$2" && exit 0
        ;;
    -h | --help)
        printf "%s\t${green}Usage: asn-scan subcommand <asn-number>OR<cidr-number>${reset}\n\n\t${yellow}Example (scanning asn): asn-scan {-a|--asn} 15169 \n\tExample (scanning cidr): asn-scan {-c|--cidr} 8.8.4.4.0/24' ${reset}\n" && exit 0
        ;;
    *)
        printf "%s\n\t${red}Invalid option: ${1}\n\tuse netscan -h or --help for help\n\n${reset}" && exit 0
        ;;
    esac
done
