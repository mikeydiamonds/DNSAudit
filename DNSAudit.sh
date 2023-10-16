#!/bin/bash

# DNSAudit - modified from Tom Lawrence's 2023 DNS provider audit
# https://youtu.be/NUT4K3tk9Ns?si=cwaHKuN-JSRcOwnz
# author: Mikey Pruitt - https://www.linkedin.com/in/roadtoCISO/

# file name/path of domain list
domain_list='domains.txt' # one FQDN per line in file

# get and prepare the compromised domain list from Zonefiles
wget -q "https://zonefiles.io/f/compromised/domains/live/" -O temp.txt  # download the domain list
grep -E '^[a-zA-Z0-9-]+\.(com|net)$' temp.txt >domains.txt              # extract just root .com and .net domains
# sed -i '' '50,$ d' domains.txt                                        # truncate domain list to 50 for development
sort -t= domains.txt -o domains.txt                                     # sort the domains alphabetically, why not ;)D
rm temp.txt                                                             # remove the temp file

# set variables for pretty terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'
domainlist='domainlist.csv'

# IP address of the nameserver used for lookups
# some of the services require an account and some minimal setup
# for DNSFilter, Umbrella, Cloudflare Gateway, and NextDNS:
# 1. Create a free account
# 2. Add your audit location's WAN IP to the service
# 3. Create a policy to block all threats
# 4. Assign that policy to the network with your WAN IP

DNSFilter='103.247.36.36'       # free trial - https://app.dnsfilter.com/signup
Umbrella='208.67.220.220'       # free trial - https://signup.umbrella.com/
UmbrellaFamily='208.67.222.123' # free - https://www.opendns.com/setupguide/#familyshield
Cloudflare='1.1.1.1'            # free - https://1.1.1.1/
CloudflareGateway='172.64.36.1' # free up to 50 users - look for Zero Trust https://dash.cloudflare.com/
CloudflareFamilies='1.1.1.2'    # free - https://1.1.1.1/family/
Google='8.8.8.8'                # free - https://developers.google.com/speed/public-dns/
Quad9='9.9.9.9'                 # free - https://www.quad9.net/
NextDNS='45.90.28.202'          # free up to 300k queries/month - https://nextdns.io/
Adguard='94.140.14.14'          # free - https://adguard-dns.io/en/public-dns.html

# seconds to wait between lookups:
loop_wait='1' # Is set to 1 second.

# create csv files to collect the results
# this csv only contains the returned IP addresses
echo "domain,DNSFilter IP,Umbrella IP,UmbrellaFamily IP,Cloudflare IP,CloudflareGateway IP,CloudflareFamilies IP,Google IP,Quad9 IP,NextDNS IP,Adguard IP" >only_ips.csv

# this csv will tell us blocked or allowed
echo "domain,DNSFilter,Umbrella,UmbrellaFamily,Cloudflare,CloudflareGateway,CloudflareFamilies,Google,Quad9,NextDNS,Adguard" >only_results.csv

# this csv will include the returned IP addresses and blocked or not
echo "domain,DNSFilter IP,DNSFilter,Umbrella IP,Umbrella,UmbrellaFamily IP,UmbrellaFamily,Cloudflare IP,Cloudflare,CloudflareGateway IP,CloudflareGateway,CloudflareFamilies IP,CloudflareFamilies,Google IP,Google,Quad9 IP,Quad9,NextDNS IP,NextDNS,Adguard IP,Adguard" >results_and_ips.csv

for domain in $( # Start looping through domains
    cat $domain_list
); do
    # get the status code of the domain using Cloudflare's 1.1.1.1
    status=$(dig @"${Cloudflare}" +time=3 +tries=1 "${domain}" | grep "status:" | cut -d" " -f6 | sed 's/.$//')

    # only proceed if the domain actually resolves and returns NOERROR
    if [ "$status" = "NOERROR" ]; then

        # pretty print the domain name to the terminal
        printf "\n${BOLD}%36s${NC}\n" "$domain"

        # using a few methods we can determine if the domain was blocked or allowed by the service audited
        # DNSFilter, Umbrella, Umbrella Family Shield, NextDNS, and Adguard all return an IP of one of their block servers
        # Cloudflare Gateway and Cloudflare for Families return 0.0.0.0 when a domain is blocked
        # Quad9 returns a status code of NXDOMAIN with Authority: 0 to indicate a block
        # Cloudflare's 1.1.1.1 and Google's 8.8.8.8 are included as a reference and provide only bare minimum DNS security
        # if no IP is returned I have assigned "null" with a "blocked" result since the domain would not be accessible

        # DNSFilter (free trial - https://app.dnsfilter.com/signup)
        DNSFilterIP=$(dig @"${DNSFilter}" +short "${domain}" | tail -n1)
        case $DNSFilterIP in
        198.251.90.70 | 198.251.90.71 | 198.251.90.72 | 45.54.28.15 | 45.54.28.11 | 127.0.0.1 | 0.0.0.0 | '') DNSFilterResult=blocked ;;
        *) DNSFilterResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$DNSFilterResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "DNSFilter:" "$DNSFilterResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "DNSFilter:" "$DNSFilterResult")

        # Umbrella (free trial - https://signup.umbrella.com/)
        UmbrellaIP=$(dig @"${Umbrella}" +short "${domain}" | tail -n1)
        case $UmbrellaIP in
        146.112.61.104 | 146.112.61.105 | 146.112.61.106 | 146.112.61.107 | 146.112.61.108 | 146.112.61.110 | 127.0.0.1 | 0.0.0.0 | '') UmbrellaResult=blocked ;;
        *) UmbrellaResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$UmbrellaResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Umbrella:" "$UmbrellaResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Umbrella:" "$UmbrellaResult")

        # Umbrella Family Shield (free - https://www.opendns.com/setupguide/#familyshield)
        UmbrellaFamilyIP=$(dig @"${UmbrellaFamily}" +short "${domain}" | tail -n1)
        case $UmbrellaFamilyIP in
        146.112.61.104 | 146.112.61.105 | 146.112.61.106 | 146.112.61.107 | 146.112.61.108 | 146.112.61.110 | 127.0.0.1 | 0.0.0.0 | '') UmbrellaFamilyResult=blocked ;;
        *) UmbrellaFamilyResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$UmbrellaFamilyResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Umbrella Family Shield:" "$UmbrellaFamilyResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Umbrella Family Shield:" "$UmbrellaFamilyResult")

        # Cloudflare (free - https://1.1.1.1/)
        CloudflareIP=$(dig @"${Cloudflare}" +short "${domain}" | tail -n1)
        case $CloudflareIP in
        127.0.0.1 | 0.0.0.0 | '') CloudflareResult=blocked ;;
        *) CloudflareResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$CloudflareResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Cloudflare:" "$CloudflareResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Cloudflare:" "$CloudflareResult")

        # Cloudflare Gateway (free up to 50 users - look for Zero Trust https://dash.cloudflare.com/)
        CloudflareGatewayIP=$(dig @"${CloudflareGateway}" +short "${domain}" | tail -n1)
        case $CloudflareGatewayIP in
        127.0.0.1 | 0.0.0.0 | '') CloudflareGatewayResult=blocked ;;
        *) CloudflareGatewayResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$CloudflareGatewayResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Cloudflare Gateway:" "$CloudflareGatewayResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Cloudflare Gateway:" "$CloudflareGatewayResult")

        # Cloudflare Families just Malware (free - https://1.1.1.1/family/)
        CloudflareFamiliesIP=$(dig @"${CloudflareFamilies}" +short "${domain}" | tail -n1)
        case $CloudflareFamiliesIP in
        127.0.0.1 | 0.0.0.0 | '') CloudflareFamiliesResult=blocked ;;
        *) CloudflareFamiliesResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$CloudflareFamiliesResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Cloudflare for Families:" "$CloudflareFamiliesResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Cloudflare for Families:" "$CloudflareFamiliesResult")

        # Google (free - https://developers.google.com/speed/public-dns/)
        GoogleIP=$(dig @"${Google}" +short "${domain}" | tail -n1)
        case $GoogleIP in
        127.0.0.1 | 0.0.0.0 | '') GoogleResult=blocked ;;
        *) GoogleResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$GoogleResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Google:" "$GoogleResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Google:" "$GoogleResult")

        # Quad9 (free - https://www.quad9.net/)
        Quad9dig=$(dig @"${Quad9}" "${domain}")
        Quad9Status=$(echo "$Quad9dig" | grep "status:" | cut -d" " -f6 | sed 's/.$//')
        Quad9Authority=$(echo "$Quad9dig" | grep "flags:" | cut -d" " -f11 | sed 's/.$//')
        Quad9IP=$(dig @"${Quad9}" +short "${domain}" | tail -n1)
        if [ "$Quad9Status" = "NXDOMAIN" ] && [ "$Quad9Authority" = 0 ]; then
            Quad9Result="blocked"
        elif [ "$Quad9IP" = '' ]; then
            Quad9Result="blocked"
        elif [ "$Quad9Status" = "NOERROR" ]; then
            Quad9Result="allowed"
        fi

        # pretty print results to the terminal
        [ "$Quad9Result" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Quad9:" "$Quad9Result") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Quad9:" "$Quad9Result")

        # NextDNS (free up to 300k queries/month - https://nextdns.io/)
        NextDNSIP=$(dig @"${NextDNS}" +short "${domain}" | tail -n1)
        case $NextDNSIP in
        64.187.227.105 | 45.32.219.28 | 45.90.28.202 | 45.90.30.202 | 127.0.0.1 | 0.0.0.0 | '') NextDNSResult=blocked ;;
        *) NextDNSResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$NextDNSResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "NextDNS:" "$NextDNSResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "NextDNS:" "$NextDNSResult")

        # Adguard (free - https://adguard-dns.io/en/public-dns.html)
        AdguardIP=$(dig @"${Adguard}" +short "${domain}" | tail -n1)
        case $AdguardIP in
        94.140.14.33 | 127.0.0.1 | 0.0.0.0 | '') AdguardResult=blocked ;;
        *) AdguardResult=allowed ;;
        esac

        # pretty print results to the terminal
        [ "$AdguardResult" = "blocked" ] && (printf "${BLUE}%26s${NC}  ${GREEN}%8s${NC}\n" "Adguard:" "$AdguardResult") || (printf "${BLUE}%26s${NC}  ${RED}%8s${NC}\n" "Adguard:" "$AdguardResult")

        # write results to our csv files
        # the ${ServiceName:=null} syntax assigns null if no IP was returned
        echo "$domain,${DNSFilterIP:=null},${UmbrellaIP:=null},${UmbrellaFamilyIP:=null},${CloudflareIP:=null},${CloudflareGatewayIP:=null},${CloudflareFamiliesIP:=null},${GoogleIP:=null},${Quad9IP:=null},${NextDNSIP:=null},${AdguardIP:=null}" >>only_ips.csv

        echo "$domain,$DNSFilterResult,$UmbrellaResult,$UmbrellaFamilyResult,$CloudflareResult,$CloudflareGatewayResult,$CloudflareFamiliesResult,$GoogleResult,$Quad9Result,$NextDNSResult,$AdguardResult" >>only_results.csv

        echo "$domain,${DNSFilterIP:=null},$DNSFilterResult,${UmbrellaIP:=null},$UmbrellaResult,${UmbrellaFamilyIP:=null},$UmbrellaFamilyResult,${CloudflareIP:=null},$CloudflareResult,${CloudflareGatewayIP:=null},$CloudflareGatewayResult,${CloudflareFamiliesIP:=null},$CloudflareFamiliesResult,${GoogleIP:=null},$GoogleResult,${Quad9IP:=null},$Quad9Result,${NextDNSIP:=null},$NextDNSResult,${AdguardIP:=null},$AdguardResult" >>results_and_ips.csv

        # sleep $loop_wait # pause before the next lookup to avoid flooding NS

    else
        :
    fi
done
