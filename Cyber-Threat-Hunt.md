$${{\color{RoyalBlue}\Huge{\textsf{The\ Great\ Admin\ Heist}}}}\$$

---
${{\color{Teal}\Huge{\textsf{Scenario}}}}\$

At Acme Corp, the eccentric yet brilliant IT admin, Bubba Rockerfeatherman III, isn’t just patching servers and resetting passwords — he’s the secret guardian of trillions in digital assets. Hidden deep within encrypted vaults lie private keys, sensitive data, and intellectual gold... all protected by his privileged account.

But the shadows have stirred.
A covert APT group known only as The Phantom Hackers 👤 has set their sights on Bubba. Masters of deception, they weave social engineering, fileless malware, and stealthy persistence into a multi-stage campaign designed to steal it all — without ever being seen.

The breach has already begun.
Using phishing, credential theft, and evasive tactics, the attackers have infiltrated Acme’s network. Bubba doesn’t even know he's compromised.

${{\color{Teal}\Huge{\textsf{Mision}}}}\$

Hunt through Microsoft Defender for Endpoint (MDE) telemetry, analyze signals, query using KQL, and follow the breadcrumbs before the keys to Bubba’s empire vanish forever.

- Known Information:
- DeviceName: anthony-001
- RemoteSessionIP: 192.168.0.110
---

${{\color{Teal}\Huge{\textsf{Flag 1: Identify the Fake Antivirus Program Name}}}}\$ <br>

Objective:
- Determine the name of the suspicious or deceptive antivirus program that initiated the security incident.

What to Hunt:
- Look for the name of the suspicious file or binary that resembles an antivirus but is responsible for the malicious activity.

Thought:
- This step is critical for attribution. Identifying the root artifact allows analysts to formulate a hypothesis and determine the origin of the malicious chain of events.

Hints:
1. Platform we use in our company
2. Program name likely begins with the following letters: A, B, or C
3. Contains

```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where (FileName startswith "A" or FileName startswith "B" or FileName startswith "C") 
    and FileName endswith ".exe"
| distinct FileName
```
From the results returned I concluded that the only possible correct answer based of hint 1 would be BitSentinelCore.exe
- Answer: BitSentinelCore.exe

---
${{\color{Teal}\Huge{\textsf{Flag 2: Malicious File Written Somewhere}}}}\$<br>

Objective:
- Confirm that the fake antivirus binary was written to the disk on the host system.

What to Hunt:
- Identify the one responsible for dropping the malicious file into the disk.

Thought:
- This validates the delivery mechanism of the dropper and supports behavioral indicators of compromise, particularly in directories often used by malware.

Hints:
1. Legit software
2. Microsoft
3. Three
```
DeviceFileEvents
| where FileName == "BitSentinelCore.exe"
| where ActionType in ("FileCreated", "FileModified", "FileWritten")
| project InitiatingProcessFileName
```
Answer: csc.exe

---
${{\color{Teal}\Huge{\textsf{Flag 3: Execution of the Program}}}}\$

Objective:
- Verify whether the dropped malicious file was manually executed by the user or attacker.

What to Hunt:
- Search for process execution events tied to the suspicious binary.

Thought:
- Execution of the file marks the start of the malicious payloads being triggered, indicating user interaction or attacker initiation.

Hint:
1. Bubba clicked the .exe file himself

Answer:BitSentinelCore.exe

---
${{\color{Teal}\Huge{\textsf{Flag 4: Keylogger Artifact Written}}}}\$<br>

Objective:
- Identify whether any artifact was dropped that indicates keylogger behavior.

What to Hunt:
- Search for any file write events associated with possible keylogging activity.

Thought:
- This confirms credential harvesting or surveillance behavior linked to the fake antivirus binary.

Hints:
1. ."a rather efficient way to completing a complex process" 
2. News

Side note: This flag gave me a bit of trouble as well as other community members. I was instructed to look and see what files are created by the file I discovered in flag #3. Doing so, led me to a file called ThreatMetrics. Which was the incorrect answer for the flag. I then decided to shift my focus to see what files where within the folder path associated wit the fake antivirus. My query used to discover the flag is provided below:

```
DeviceFileEvents
| where DeviceName contains "anthony-001"
| where FolderPath contains @"C\Users\4nth0ny!\AppData\Roaming"
```
Answer:systemreport.lnk

---
${{\color{Teal}\Huge{\textsf{Flag 5: Registry Persistence Entry}}}}\$<br>

Objective:
- Determine if the malware established persistence via the Windows Registry.

What to Hunt:
- Look for registry modifications that enable the malware to auto-run on startup.

Thought:
- This flag reveals how the malware achieves persistence across system reboots or logins, helping track long-term infection.

Hint:
1. Long answer
Identify the full Registry Path value

- To solve this flag I switched to the DeviceRegistryEvents table. The folloing query used was:
```
DeviceRegistryEvents
| where RegistryValueData has "bitsentinelcore.exe"
```
- There was only one field underneath result

Answer: HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

---
${{\color{Teal}\Huge{\textsf{Flag 6: Daily Scheduled Task Created}}}}\$<br>

Objective:
- Identify the value proves that the attacker intents for long-term access

What to Hunt:
- Identify name of the associated scheduled task.

Thought:
- Without detecting this task, participants might miss that the system stays infected beyond just running the dropper once.

Hints:
1. Three
2. Fitness
What is the name of the created scheduled task?

For this flag, I utilzed the Process Events Table as well as the known fake antivirus.
```
DeviceProcesEvents
| where ProcessCommandLine has "BitsentinelCore.exe"
| where DeviceName contains "anthony-001"
| where FileName has "schtasks.exe"
```
This query lead. to 3 results in which further inspection of the command line field would lead to the nae of the scheduled task.

Answer:UpdateHealthTelemetry

---
${{\color{Teal}\Huge{\textsf{Flag7: Process Spawn Chain}}}}\$<br>

Objective:
- Understand the full chain of process relationships that led to task creation.

What to Hunt:
- Trace the parent process that led to cmd.exe, and subsequently to schtasks.exe.

Thought:
- Illustrates how the attacker leveraged process relationships to implement persistence, providing insight into the execution flow.

Format: 
parent -> child -> grandchild

Hint: (how the answer should look)
bubba.exe -> newworldorder.exe -> illuminate.exe
Provide the kill chain

- This flag did not necessarily require a query as it was a bit more simplier based on information form the previous flags.

Answer: BitSentinelCore.exe -> cmd.exe -> schtasks.exe

---
${{\color{Teal}\Huge{\textsf{Flag 8: Timestamp Correlation}}}}\$<br>

Objective:
- Correlate all observed behaviors to a single initiating event

What to Hunt:
- Compare timestamps from the initial execution to file creation, registry modification, and task scheduling.

Thought:
- Builds a forensic timeline that strengthens cause-and-effect analysis, confirming that all actions originated from the execution of the fake antivirus program. 

Provide the timestamp of the leading event that's causing all these mess

- This flag can simply be found by referencing back to the fake antvirus found in Flag #1.
```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where (FileName startswith "A" or FileName startswith "B" or FileName startswith "C") 
    and FileName endswith ".exe"
| project Timestamp
```
Answers: 2025-05-07T02:00:36.794406Z
