DeviceProcessEvents
| where Timestamp >= datetime(2025-06-14) and Timestamp <= datetime(2025-06-18)  // Focus on June 15-17
| where FolderPath has @"C:\Windows\Temp\" and FolderPath contains "dism" // Filter for activity in the Temp folde
|where ActionType == "ProcessCreated"
| sort by Timestamp desc
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
