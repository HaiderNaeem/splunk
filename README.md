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
