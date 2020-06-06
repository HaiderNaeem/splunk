# Ransomware Analysis

-> Sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 | eval cmdlen=len(CommandLine) | eventstats avg(cmdlen) as avg, stdev(cmdlen) as stdev by host | stats max(cmdlen) as maxlen, values(avg) as avgperhost, values(stdev) as stdevperhost by host, CommandLine | eval threshold = avgperhost + ( 4 * stdevperhost) | where maxlen > threshold


- Windows Sysmon events contain detailed endpoint activities that can help locate ransomeware. 
- Logs can indicate if the user downloaded and opened an attachment from email, and accidently ran the ransomeware script
- Malware tends to use long lines of instructions usually 4 times the deviation
- sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" // grab logs from ms sysmon
- EventCode=1 // shows which process starts took place, 
- The Eval function can be used to calculate the length of the variables for the cmdlen field
- sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 | eval cmdlen=len(CommandLine) // this will create a new field named cmdlen
- The eventstats command to make an avaergae threshold with standard deviation so that maliciosu processes can be seperated from normal ones
- Sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 | eval cmdlen=len(CommandLine) | eventstats avg(cmdlen) as avg, stdev(cmdlen) as stdev by host // each host will have its own standard deviation and average command length because average command line length varies by system and user
- To summarize the data in tabular format the stats command can be used
- Sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 | eval cmdlen=len(CommandLine) | eventstats avg(cmdlen) as avg, stdev(cmdlen) as stdev by host | stats max(cmdlen) as maxlen, values(avg) as avgperhost, values(stdev) as stdevperhost by host, CommandLine
- Next using the eval command the threshold can be calculated for normal process
- This should give out any processes whose command line cariables were 4 times the standard deviation of the normal processes in a particular host.

# Vulnerability Detections

Check windows update log:
-> index=* (sourcetype="*wineventlog:system" OR sourcetype="winupdatelog") (KB12020 OR KB0303 ...) | stats latest(status) as laststatus by _time , dest, signature, signatue_id | search laststatus=installed

- Open splunk security essentials for ransomeware app
- Click on ransomware vunerabilities use case, scan enviroment for specific cve's
- Data should show any vulnerable systems/endpoints from scans(from  eg nessus) in a particular time frame
- Check if systems are patched from the universal forwarder with "monitor successful windows updates" feature

# Unusual Traffic: TOR, SMB, DNS QUERIES, HTTP
-> index=* (( tag=network tag=communicate) OR (sourcetype=pan*traffic OR sourcetype=opsec OR sourcetype=cisco:asa OR sourcetype=stream* )) app=tor src=ip* | table _time src_ip src_port dest_ip dest_port bytes app

- splunk security essentials app -> network features
- ransome usually uses TOR 
- looks for the network traffic data in splunk
- creating a splunk search for endpoint talking to different countries can also indicate the presence of tor

-> index=* (( tag=network tag=communicate) OR (sourcetype=pan*traffic OR sourcetype=opsec OR sourcetype=cisco:asa OR sourcetype=stream* )) action=allowed (app=smb OR dest_port=139 OR dest_port=445) | bucket _time span=id | stats count by _time src_ip dest_ip dest_port

- smb traffic typically should not be allowed outside of firewall,
- ransomeware usaully makes quesries on port 445/139 for smb or query external hosts on smb

-> index=* sourcetype=XmlWinEventlog:Microsoft-Windows-Sysmon/Operational EventCode=3 Image=*.exe (dest_port=139 OR dest_port=445) | stats dc(DestinationIp) as "Destinations", values(DestinationIp) as "IPs" values(DestinationPort) as "DestPorts" by Image | rename Image as MaliciousProcess  

- To find the unusual executable making the smb queries windows sysmon logs can be used
- Sysmon can capture network connections which are presented as Eventcode=3
- Once again this can be used to filter out smb traffic going out of the user space

-> index*= EventCode=1 Image="C:\\Users\\bob\\Desktop\\process.exe" 

- EventCode=1 with windows sysmon indicates a process start
- Sysmon also hashes (sha1) the code of the process that starts with event code 1
- Paste hash on VirusTotal

-> index=* host=pcName sourcetype="stream:dns" "query_type{}"=PTR | spath="hostname{}" | search ("hostname{}"="*" AND "hostname{}"!="*.local" AND "hostname{}" !="*.arpa") | stats count by hostname{},name{} | rename hostname{} as domain, name{} as IP | eval list = "iana" | 'ut_parse(domain,list)' | dedup ut_domain | lookup alexa-1m.csv domain as ut_domain | lookup cdn.csv domain as ut_domain | search NOT cdn_provider="*" | regex rank!="\d+" | iplocation IP | fields IP, ut_domain,rank, count, Country | sort - Count 

- Lookup if the endpoints are connecting to proper domains
- ptr queries do reverse lookups for ip addresses
- popular domain are found in alexa 1million

# Finding processes that are communicating on port 80 with MS Sysmon
->index=* sourcetype=XmlWinEventlog:Microsoft-Windows-Sysmon/Operational EventCode=3 dest_port=80 | stats sparkline count by Image,DestinationIp | sort -count | iplocation DestinationIp 

# Filtering web requests that issues a purchase action
-> sourcetype=access_* status=200 action=purchase | top categoryId'

# Users that issue a download event
-> eventtype=”download” | bin _time span=1d as day | stats values(clientip) as ips dc(clientip) by day | streamstats dc(ips) as “Cumulative total”

- Streamstats command, that calculates summary statistics on search results, diagnose attempts such user privilege escalation, or arp spoofing attacks.
- Bin, breaks time into days
- Stats command calculates the distinct users (clientip) and user count per day
- Streamstats command finds the running distinct count of users

# Analyse an arp spoofing attack

-> source=/Users/logs/arp.csv MAC= AA:BB:CC:DD:00:00 | head 10 | streamstats current=false last(IP_ADDRESS) as new_ip_addr last (_time) as time_of_change by MAC | where IP_ADDRESS!=new_i p_addr | convert ctime(time_of_change) as time_of_change | rename IP_ADDR ESS as old_ip_addr | table time_of_change, MAC, old_ip_addr, new_ip_addr


# ATM Fraud detection

sourcetype=ATM action=withdrawal | transaction customer maxspan=15m | eval location_count=mvcount(location) | where location_count>1 | stats values(location) by customer

- ATM withdrawals of funds, made by the same customer more than once in the last 15 minutes from two different cities.

# Checking for stolen credit cards

-> sourcetype=card_transactions -earliest=15m | stats min(amount) as min max(amount) as max by customer | where min<50 AND max>500|table min, max, customer
