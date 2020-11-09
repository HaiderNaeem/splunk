# Ransomware Analysis

-> Sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 | eval cmdlen=len(CommandLine) | eventstats avg(cmdlen) as avg, stdev(cmdlen) as stdev by host | stats max(cmdlen) as maxlen, values(avg) as avgperhost, values(stdev) as stdevperhost by host, CommandLine | eval threshold = avgperhost + ( 4 * stdevperhost) | where maxlen > threshold


- Windows Sysmon events contain detailed endpoint activities that can help locate ransomeware. 
- Logs can indicate if the user downloaded and opened an attachment from email, and accidently ran the ransomeware script
- Malware tends to use long lines of instructions usually 4 times the deviation
- sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" // grab logs from ms sysmon
- EventCode=1 // shows which process starts took place, 
- The Eval function can be used to calculate the length of the variables for the cmdlen field
- sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 | eval cmdlen=len(CommandLine) // this will create a new field named cmdlen
- The eventstats command to make an avaergae threshold with standard deviation so that malicious processes can be seperated from normal ones
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

# Analysing windows registry data
-> index=* sourcetype=WinRegistry process_image="*AppData\\*" key_path="*currentversion\\run*" | table _time, host, process_image, key_path,
| sort _time

- Splunk Security Essentials for Ransomeware -> Monitor Autorun registry keys 
- Report changes to specific registry keys, from sysmon
- Malware remains persistant if the keys have been altered by it, even after reboot
- When an executable is called it adds additional info to a key path with a run key path before it, HKLM\...\...\run\maliciousProcPath
- The maliciousProcPath can be search within splunk, to see where else the pattern appeared (sourcetypes), which may show the malware associated with the path
- Can also see if the path started any process executions with the event code 1 and command line

# Users that issue a download event
-> eventtype=”download” | bin _time span=1d as day | stats values(clientip) as ips dc(clientip) by day | streamstats dc(ips) as “Cumulative total”

- Streamstats command, that calculates summary statistics on search results, diagnose attempts such user privilege escalation, or arp spoofing attacks.
- Bin, breaks time into days
- Stats command calculates the distinct users (clientip) and user count per day
- Streamstats command finds the running distinct count of users

# Windows Event Logs
-> | inputlookup UC_windows_event_log | search ((sourcetype=wineventlog:security OR XmlWinEventlog:Security) AND (EventCode=1102 OR EventCode=1100) OR ((sourcetype=wineventlog:system OR XmlWinEventlog:System) AND EventCode=104) | table _time EventCode Message sourcetype host

3 major logs, security, system and application
- windows log cheat cheet malwarearchealogy and .conf2015
- app , splunk security essential -> envent logs
- searching for event codes that indicates suspicious processes clearing event logs
 
 # Find new services installed in system that auto start , with event 7045 
-> index=* EventCode=7045 Service_Start_Type="auto start" | table _time, ComputerName, Service*

# Looking for vssadmin activity calls by processes to clear local system restore points
-> index=* sourcetype=wineventlog:security EventCode=4688 New_Process_Name!="C\\Windows*" [search index=* sourcetype=wineventlog:security (cmd.exe AND *vssadmin*) EventCode=4688 | dedup Creator _Process_ID | fields New_Process_ID ] | table _time, PCName, _Porcess, _Name, Process_Command_Line <- may have to manually enable this field

- [] indicates a subsearch, which will run first and then connect the result to the main search

# Underlying changes in the windows disk directory
-> index=* EventCode=4663 Accesses="WriteData (or Addfile)" Object_Name="*.exe" Process_Name="*AppData*" | table Account_Domain, Account_Name.Proecess_Name, Accesses, Object_Name

# Processes from user directories with large amount of entropy 
-> index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="C:\\Users*" | `ut_shannon(New_Process_Name)` | stats values(ut_shannon) as "Shannon Entropy Score" by New_Process_Name, host | rename New_Process_Name as Process_Name, Host as Endpoint | sort -"Shannon Entropy Score"

# Task scheduler event calling and creating a task only to run once
-> index=* sourcetype="wineventlog:security" schtasks.exe once | table host,New_ProcessName, Process_Command_Line, memeber_id

# Analyse an arp spoofing attack
-> source=/Users/logs/arp.csv MAC= AA:BB:CC:DD:00:00 | head 10 | streamstats current=false last(IP_ADDRESS) as new_ip_addr last (_time) as time_of_change by MAC | where IP_ADDRESS!=new_i p_addr | convert ctime(time_of_change) as time_of_change | rename IP_ADDR ESS as old_ip_addr | table time_of_change, MAC, old_ip_addr, new_ip_addr

# Analysis with MS Sysmon
Malware usually replicates legit ms processes name but may not run in the proper directory/disk
-> index=* (sourcetype=min*security EventCide=4688 New_Process_Name!=*Windows\\System32* New_Process_Name!=*Windows\\SysWOW64*) OR (sourcetyoe=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 Image!=*Windows\\System32* Image!=*Windows\\SysWOW64*) | eval process=coalesce(Image, New_Process_Name) | rex field=process .*\\\(?<filename>\S+)\s?$ | lookup isWindowsSystemFile_lookup filename | search systemFile=true | table _time dest host user process
 
# Sysmon example of malicious executable manupilating file system executables
-> index=* sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 (attrib* OR icacls*) | _time,User,Computer,EXEDirectory,CommandLine

# Finding spoofed preocesses with sysmon using tstat cmmand
-> | tstats count FROM datamodel=Application_State.All_Application_State WHERE (All_Application_State.process!="C:\\Windows\\System32*" AND All_Application_State.process!="C:\\Windows\\SysWOW64*") BY _time,host, All_Application_State.process, All_Application_State.user | rex field=process .*\\\(?<filename>\S*)\s?$ | lookup windowsSystemFiles.csv filename | search isWindowsSystemFile=1 

# Porgram like MsOffice launching an executable
-> index=* sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational EventDescription="Process Create" (vbs OR *.exe) [search index=* source=sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" (WINWORD OR EXCEL) EventDescription="Process Create" | dedup ProcessGuid | rename ProcessGuid as ParentProcessGuid | fields ParentProcessGuid ] | table _time,host,ProcessGuid,ParentProcessGuid,Image,ParentImage

# Show Parent/Child relationship for vssadmin activity
-> index=* EventCode=1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" vssadmin | stats values(PercentImage) as Parent_Process, Values(Image) as Current_Process,values(CommandLine) as Current_Command_Line by _time,host,user

# Malicious Process modifying more than a 100 files per minute
-> index=* sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational EventCode=1 (Image!="C:\\Windows*" Image=*.exe Image!="C:\\Program Files*") [search index=* host=* sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational | streamstats time_windows=1m count as "new_files" by host | search new_files>100 | fields Image] | table host, Image, sha1 | dedup sha1
- provided the process is found, research the exe hash in virustotal

# ATM Fraud detection

sourcetype=ATM action=withdrawal | transaction customer maxspan=15m | eval location_count=mvcount(location) | where location_count>1 | stats values(location) by customer

- ATM withdrawals of funds, made by the same customer more than once in the last 15 minutes from two different cities.

# Checking for stolen credit cards

-> sourcetype=card_transactions -earliest=15m | stats min(amount) as min max(amount) as max by customer | where min<50 AND max>500|table min, max, customer
