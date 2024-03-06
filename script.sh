#!/bin/bash

function run_command_with_progress() {
    command=$1
    echo -n "Running $command..."
    eval "$command" &
    pid=$!
    while kill -0 $pid 2>/dev/null; do
        echo -n "."
        sleep 1
    done
    wait $pid
    echo "Done"
}

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <web_application_url>"
    exit 1
fi

web_url=$1

# Get IP address using nslookup
run_command_with_progress "nslookup $web_url | awk '/^Address: / { print \$2 }'"

# Use nmap to scan for open ports
run_command_with_progress "nmap -p- --open $ip_address | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//'"

# Use curl to get headers and find tech stack
run_command_with_progress "curl -I $web_url 2>/dev/null | grep -i 'server\|x-powered-by\|tech\|framework'"

# Try to identify the web server software
web_server=$(echo "$headers" | grep -i 'server' | awk '{print $2}')

# Try to identify the technology or framework being used
tech_stack=$(echo "$headers" | grep -i 'x-powered-by\|tech\|framework' | awk '{print $2}')

# Use curl to get HTML content and find database information
run_command_with_progress "curl -s $web_url | grep -i 'mysql\|pgsql\|mongodb\|sqlite\|oracle'"

# Use dirb to find directories and subdirectories
run_command_with_progress "dirb $web_url -o /dev/null 2>/dev/null | grep '+ '"

# Use curl to get HTML content
run_command_with_progress "curl -s $web_url"

# Run vulnerability scans
run_command_with_progress "bed -q -i $ip_address -p $open_ports"
run_command_with_progress "ohrwurm -u $web_url"
run_command_with_progress "nikto -h $web_url"
run_command_with_progress "sqlmap -u $web_url --batch"

# Additional Tools
run_command_with_progress "recon-ng -r $web_url"
run_command_with_progress "theharvester -d $web_url -l 500 -b all"
run_command_with_progress "dnsrecon -d $web_url"
run_command_with_progress "netdiscover -r $ip_address"
run_command_with_progress "unicornscan $ip_address"
run_command_with_progress "masscan -p1-65535 $ip_address"
run_command_with_progress "p0f -i eth0 -p -O $ip_address"
run_command_with_progress "w3af_console -s 'crawl, audit' -t 5 -T $web_url"
run_command_with_progress "openvas --target $ip_address --port $open_ports"
run_command_with_progress "sqlninja $web_url"
run_command_with_progress "ptf --script web/xxx"
run_command_with_progress "jsql-injection $web_url"
run_command_with_progress "exploitpack -t $web_url"

# Additional Tools
run_command_with_progress "dmitry -winsepfb $web_url"
run_command_with_progress "maltego $web_url"
run_command_with_progress "ohrwurm -u $web_url"
run_command_with_progress "powerfuzzer -u $web_url"
run_command_with_progress "sfuzz -u $web_url"
run_command_with_progress "siparmyknife -r $web_url"
run_command_with_progress "webscarab"
run_command_with_progress "httrack $web_url"
run_command_with_progress "vega -u $web_url"
run_command_with_progress "tmscmd10g $web_url"
run_command_with_progress "oscanner -s $web_url"
run_command_with_progress "bbsql -u $web_url"
run_command_with_progress "armitage"
run_command_with_progress "empire"
run_command_with_progress "pupy"
run_command_with_progress "koadic"
run_command_with_progress "dnscat2"
run_command_with_progress "mimikatz"
