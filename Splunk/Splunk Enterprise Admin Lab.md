
  $${{\color{Yellow}\huge{\textsf{Splunk Enterprise Lab\ }}}}\$$

---
$${{\color{Silver}\huge{\textsf{Summary }}}}\$$

---
In this lab I set up a splunk enviroment consisiting of:
| VM  | OS             | Role(s)                                                                          |
| --- | -------------- | -------------------------------------------------------------------------------- |
| VM1 | RHEL 9         | **Universal Forwarder (UF)** + **Indexer**                                       |
| VM2 | Windows Server | **Search Head (SH)** + **Deployment Server (DS)** + **Universal Forwarder (UF)** |;

The goal was to simulate a small-scale Splunk deployment, including forwarding logs from multiple sources, indexing them centrally, and managing configurations via a deployment server.



<div align="center">
 <img src =https://github.com/CyberFlash1/Flash028/blob/8db593eba15323bfb0af3dd0e8e80b111a7cc915/Splunk/splunk%20enterprise%20lab.png width="500">
</div>
  </br>

${{\color{Yellow}\large{\textsf{1️⃣ RHEL Universal Forwarder + Indexer (VM1)\ }}}}\$

Step 1: Download Splunk
```
# Download Splunk Enterprise
wget -O splunk-10.0.2-linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-x86_64.tgz"

# Extract
tar -xvzf splunk-10.0.2-linux-x86_64.tgz -C /opt/
```
${{\color{Yellow}\large{\textsf{Step 2: Install Universal Forwarder (UF)\ }}}}\$
```
# Download UF
wget -O splunkforwarder-10.0.2-linux-x86_64.tgz "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-x86_64.tgz"

# Extract
tar -xvzf splunkforwarder-10.0.2-linux-x86_64.tgz -C /opt/
```
${{\color{Yellow}\large{\textsf{Step 3: Start Splunk Services\ }}}}\$
```
# Start Splunk Enterprise
/opt/splunk/bin/splunk start --accept-license

# Enable boot-start
/opt/splunk/bin/splunk enable boot-start

# Start Universal Forwarder
/opt/splunkforwarder/bin/splunk start --accept-license
/opt/splunkforwarder/bin/splunk enable boot-start
```
```
# Set the Indexer IP (assuming VM1 also acts as indexer)
sudo /opt/splunkforwarder/bin/splunk add forward-server <Indexer-IP>:9997

# Add monitor to watch /var/log/messages
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/messages
```
${{\color{Yellow}\large{\textsf{2️⃣ Windows Search Head + Deployment Server + UF (VM2)s\ }}}}\$
```
# Run installer
msiexec /i splunk-10.0.2-x64-release.msi AGREETOLICENSE=Yes

# Start Splunk Enterprise
"C:\Program Files\Splunk\bin\splunk.exe" start
```
Step 3: Configure Deployment Server
Navigate to Settings → Forwarder Management
Add server class and assign deployed UFs
Point clients (UFs) to DS IP
Step 4: Install Universal Forwarder
```
# Run UF installer
msiexec /i splunkforwarder-10.0.2-x64-release.msi AGREETOLICENSE=Yes

# Configure UF to send logs to Indexer (VM1)
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add forward-server <Indexer-IP>:9997

# Monitor local Windows Event Logs
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add monitor "C:\Windows\System32\winevt\Logs"
```
${{\color{Orange}\huge{\textsf{Outcome}}}}$
Successfully set up a 2-node Splunk environment
- RHEL UF sending Linux logs → Indexer
- Windows UF sending Windows Event Logs → Indexer
- Deployment Server managing configuration updates to UFs
- Verified logs appearing in Search Head, confirming end-to-end data flow
```
