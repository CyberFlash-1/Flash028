![image](https://github.com/user-attachments/assets/ffc577ce-8692-4ea7-b633-f0da774c46ce)

# 🛡️ STIG Remediation Documentation

This repository documents remediations for STIG (Security Technical Implementation Guide) findings across multiple systems. Use this as a reference for securing systems in alignment with DISA STIG guidelines.

---

## Table of Contents

- [Systems Covered](#systems-covered)
- [WN10-AU-000035](#wn10-au-000035)
- [WN10-AU-000500](#wn10-au-000500)
- [WN10-CC-000005](#wn10-au-000005)
- 
---

## Systems Covered

| System              | STIG Version | Last Updated |
|---------------------|--------------|--------------|
| Windows Server 2016 | v2r6         | Apr 2025     |
---



## WN10-AU-000035 
The system must be configured to audit Account Management - User Account Management failures.

- **Severity:** High
- **Description:** The system must be configured to audit Account Management - User Account Management failures.
- Solution:Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management >> 'Audit User Account Management' with 'Failure' selected.
  
**Fix Text**<br>
1. Configure the system to audit failures for User Account Management.
2.  Using Group Policy: >> Open gpedit.msc
3.  Navigate to:Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Account Management
4.  Double-click User Account Management
5.  Check Configure the following audit events > Failure
6.   Click Apply and OK
  
- PowerShell Remediation
```
AuditPol /set /subcategory:"User Account Management" /failure:enable
```
---

## WN10-AU-000500
The Application event log size must be configured to 32768 KB or greater.

- **Severity:** High
- **Description:**The Application event log size must be configured to 32768 KB or greater.
- Solution:If the system is configured to send audit records directly to an audit server, this is NA. This must be documented with the ISSO. Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Application >> 'Specify the maximum log file size (KB)' to 'Enabled' with a 'Maximum Log Size (KB)' of '32768' or greater.

**Fix Text**<br>
1. Configure the policy value for Computer Configuration
2. Administrative Templates Windows Components
3. Event Log Service >> Application
4. 'Specify the maximum log file size (KB)' to 'Enabled' with a 'Maximum Log Size (KB)' of '32768' or greater.
  
- PowerShell Remediation
```
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" `
  -Name "MaxSize" -PropertyType DWord -Value 32768 -Force
```
---
1. Open **Group Policy Management Editor** (`gpedit.msc`)  
2. Navigate to:  
 `Computer Configuration → Administrative Templates → Control Panel → Personalization`  
3. Double-click **Prevent enabling lock screen camera**  
4. Select **Enabled**  
5. Click **Apply** and **OK**

---
## WN10-CC-000005
Camera access from the lock screen must be disabled.

- **Severity:** High
- **Description:**Camera access from the lock screen must be disabled.
- Solution:If the device does not have a camera, this is NA. Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> 'Prevent enabling lock screen camera' to 'Enabled'

**Fix Text**<br>
1. If the device does not have a camera, this is NA. Configure the policy value for
2. Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> 'Prevent enabling lock screen camera' to 'Enabled'

- PowerShell Remediation

```powershell
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" `
-Name "NoLockScreenCamera" -PropertyType DWord -Value 1 -Force
