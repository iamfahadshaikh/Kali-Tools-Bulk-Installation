#!/bin/bash

# Reconnaissance Tools
recon_tools=(
    "lanmaster53/recon-ng"
    "laramies/theHarvester"
    "nmap/nmap"
    "darkoperator/dnsrecon"
    "alexxy/netdiscover"
    "unicornscan/unicornscan"
    "lockfale/osint"
    "robertdavidgraham/masscan"
    "p0f/p0f"
    "maK-/parameth"
    "hakluke/hakrawler"
    "hakluke/ghaudra"
    "projectdiscovery/naabu"
    "Bo0oM/ParamPamPam"
    "ParaMiner/ParaMiner"
    "trimstray/sandmap"
    "skavngr/rapidscan"
    "projectdiscovery/shuffledns"
    "Screetsec/Sudomy"
    "haccer/subjack"
    "Ice3man543/SubOver"
    "devanshbatham/Sublist3r"
    "rverton/webanalyze"
    "tomnomnom/waybackurls"
    "xmendez/wfuzz"
)

# Vulnerability Scanning Tools
vuln_scanning_tools=(
    "greenbone/openvas"
    "andresriancho/w3af"
    "zaproxy/zaproxy"
    "portswigger/burp-suite"
    "sullo/nikto"
    "bedzinsoft/bed"
    "ohwurm/Ohwurm"
    "digininja/Powerfuzzer"
    "nccgroup/sfuzz"
    "iphelix/SIPArmyKnife"
)

# Web Application Analysis Tools
web_app_analysis_tools=(
    "sqlmapproject/sqlmap"
    "tomnomnom/hacks"
    "golismero/golismero"
    "wpscanteam/wpscan"
    "commixproject/commix"
    "s0md3v/Corsy"
    "shivangx01b/Corsme"
    "cnotin/SignedCRLf"
    "wireghoul/dotdotpwn"
    "fuzzapi/fuzzapi"
    "fuzzdb-project/fuzzdb"
    "tarunkant/Gopherus"
    "linuz/Stunning-Headshot"
    "technion/injectus"
    "doyensec/inql"
    "hvqzao/liffy"
    "projectdiscovery/nuclei"
    "j3ssie/Osmedeus"
    "ParaMiner/ParaMiner"
    "Bo0oM/ParamPamPam"
    "geraldioc/shapeshifter"
    "defparam/smuggler"
    "swisskyrepo/SSRFmap"
    "s0md3v/Striker"
    "0xbug/SQLiScanner"
    "m4ll0k/takeover"
    "rverton/webanalyze"
    "xmendez/wfuzz"
    "0xInfection/XSRFProbe"
    "s0md3v/XSStrike"
)

# Database Assessment Tools
db_assessment_tools=(
    "aleenzz/BSQLInjector"
    "ron190/jsql-injection"
    "foospidy/oscanner"
    "sqlmapproject/sqlmap"
    "sqlninja/sqlninja"
    "gh0x0st/TMSCMD10G"
)

# Password and Bruteforce Attacks Tools
password_bruteforce_tools=(
    "openwall/john"
    "hashcat/hashcat"
    "vanhauser-thc/thc-hydra"
    "project-rainbowcrack/rainbowcrack"
    "crunchsec/crunch"
    "jmk-foofus/medusa"
    "digininja/cewl"
    "lanjelot/patator"
    "nmap/ncrack"
    "shinnok/johnny"
    "jmk-foofus/medusa"
)

# Exploitation Tools
exploitation_tools=(
    "Armitage-Metasploit/armitage"
    "metasploit/metasploit-framework"
    "offensive-security/exploitdb"
    "beefproject/beef"
    "metasploit/metasploit-framework"
    "sqlmapproject/sqlmap"
    "trustedsec/ptf"
    "ron190/jsql-injection"
    "sqlmapproject/sqlmap"
    "exploitpack/exploitpack"
    "Arachni/arachni"
    "beefproject/beef"
    "1N3/BlackWidow"
    "EagleSecurity/eagle"
    "1N3/Findsploit"
    "cloudflare/flare"
    "vulnersCom/getsploit"
    "1N3/IntruderPayloads"
    "jaeles-project/jaeles"
    "projectdiscovery/nuclei"
    "j3ssie/Osmedeus"
    "shodan/shodan-python"
    "sqlmapproject/sqlmap"
    "zaproxy/zaproxy"
)

# Reporting and Documentation Tools
reporting_tools=(
    "dradis/dradis-ce"
    "infobyte/faraday"
    "SerpicoProject/Serpico"
    "dradis/dradis-ce"
    "infobyte/faraday"
    "digininja/pipal"
    "unicornsflyinonmagictrees/MagicTree"
)

# Social Engineering Tools
social_engineering_tools=(
    "trustedsec/social-engineer-toolkit"
    "getgophish/gophish"
    "securestate/king-phisher"
    "rezaaksa/PhishX"
    "trustedsec/social-engineer-toolkit"
    "040hosting/Backdoor-F"
    "savio-code/ghost-phisher"
)

# Mobile Security Tools
mobile_security_tools=(
    "mwrinfosecurity/drozer"
    "androguard/androguard"
    "frida/frida"
    "MobSF/Mobile-Security-Framework-MobSF"
)

# Wireless Network Attacks Tools
wireless_network_tools=(
    "DanMcInerney/LANs.py"
    "derv82/wifite"
    "wiire/pixiewps"
    "ebrake/Netcat"
    "t6x/reaver-wps-fork-t6x"
    "kismetwireless/kismet"
    "ettercap/ettercap"
    "aircrack-ng/aircrack-ng"
    "savio-code/fern-wifi-cracker"
    "savio-code/ghost-phisher"
    "derv82/wifite"
)

# Post Exploitation Tools
post_exploitation_tools=(
    "BC-SECURITY/Empire"
    "n1nj4sec/pupy"
    "zerosum0x0/koadic"
    "iagox86/dnscat2"
    "gentilkiwi/mimikatz"
    "BloodHoundAD/BloodHound"
)

# Reverse Engineering Tools
reverse_engineering_tools=(
    "ibotpeaches/Apktool"
    "DeNations/flashm"
    "botherder/flashm"
    "nasm/nasm"
)

# Sniffing and Spoofing Tools
sniffing_spoofing_tools=(
    "wireshark/wireshark"
    "bettercap/bettercap"
    "ettercap/ettercap"
    "rix1337/Hamster"
    "deiv/driftnet"
    "lgandx/Responder"
)


# Forensics Tools
forensics_tools=(
    "sleuthkit/autopsy"
    "ReFirmLabs/binwalk"
    "reyammer/binwalk"
    "security-database/galleta"
    "md5deep/md5deep"
    "CIRCL/volafox"
    "volatilityfoundation/volatility"
)

# Other Tools
other_tools=(
    "Edu4rdSHL/findomain"
    "lc/gau"
    "gh0st27/GHauri"
    "hakluke/hakrawler"
    "robertdavidgraham/masscan"
    "blechschmidt/massdns"
    "projectdiscovery/naabu"
    "Bo0oM/ParamPamPam"
    "maK-/parameth"
    "ParaMiner/ParaMiner"
    "trimstray/sandmap"
    "skavngr/rapidscan"
    "projectdiscovery/shuffledns"
    "Screetsec/Sudomy"
    "haccer/subjack"
    "Ice3man543/SubOver"
    "devanshbatham/Sublist3r"
    "rverton/webanalyze"
    "tomnomnom/waybackurls"
    "xmendez/wfuzz"
)

# Function to clone repositories and install dependencies
clone_and_install() {
    for tool in "${@}"; do
        # Extract repository name from the GitHub URL
        repo_name=$(basename "${tool}")
        repo_name=${repo_name%.*}

        # Clone the repository
        git clone "https://github.com/${tool}.git" || { echo "Failed to clone ${tool}"; continue; }

        # Navigate into the cloned repository
        cd "${repo_name}" || { echo "Failed to enter ${repo_name} directory"; continue; }

        # Check for requirements.txt file and install dependencies
        if [ -f "requirements.txt" ]; then
            echo "Installing dependencies for ${repo_name}..."
            pip install -r requirements.txt || { echo "Failed to install dependencies for ${repo_name}"; }
        fi

        # Navigate back to the original directory
        cd ..
    done
}

# Clone and install tools for each category
clone_and_install "${recon_tools[@]}"
clone_and_install "${vuln_scanning_tools[@]}"
clone_and_install "${web_app_analysis_tools[@]}"
clone_and_install "${db_assessment_tools[@]}"
clone_and_install "${password_bruteforce_tools[@]}"
clone_and_install "${exploitation_tools[@]}"
clone_and_install "${reporting_tools[@]}"
clone_and_install "${social_engineering_tools[@]}"
clone_and_install "${mobile_security_tools[@]}"
clone_and_install "${wireless_network_tools[@]}"
clone_and_install "${post_exploitation_tools[@]}"
clone_and_install "${reverse_engineering_tools[@]}"
clone_and_install "${sniffing_spoofing_tools[@]}"
clone_and_install "${forensics_tools[@]}"
clone_and_install "${other_tools[@]}"

echo "All tools cloned and dependencies installed successfully!"
