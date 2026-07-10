# PowerShell Threat Hunting 
## 1. Overview 
The PowerShell Threat Hunting section documents the PowerShell queries to hunt for suspicious activity in Windows Security and Task Scheduler Operational Logs.

## 2. Hunt 1: Failed logon Activity
### Objective 
To identify the repeated failed logons which may indicate suspicious activity or a bruteforce attack.
### PowerShell Query
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
} | Select-Object TimeCreated, Id, Message | Format-List
```
### Findings 
Multiple failed authentication attempts were identified through Event ID 4625.The event details from the query were analyzed to identify the target account and correlate the timestamps of repeated failed login attempts.

## 3. Hunt 2: Unauthorized Account Creation 
### Objective 
To identify newly created local accounts that may be suspicious and potentionally provide unauthorized access to the system.
### Powershell Query 
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4720
} | Select-Object TimeCreated, Id, Message | Format-List
```
### Findings
Event ID 4720 identified the creation of the local account `helpdesk`.The event details from the query were analyzed and they showed the newly created account and the account responsible for performing the action.

## 4. Hunt 3: Privileged Group Membership Change 
### Objective
To identify accounts of privileged local groups addition and identify potential privilige access or escalation activity.
### PowerShell Query
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4732
} | Select-Object TimeCreated, Id, Message | Format-List
```
### Findings 
Event ID 4732 identified as a new member being added to the local Administrator group and by correlating the member SID with the event ID 4720 account creation , the activity has been linked to the newly created `helpdesk` account.

## 5. Hunt 4: Scheduled Task Persistence 
### Objective 
To identify the suspicious scheduled-task execution that could indicate persistence activity.
### PowerShell Query
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' |
Where-Object Id -in 200,201 |
Select-Object TimeCreated, Id, Message |
Format-List
```
### Findings
Task scheduler Operational Event IDs 200 and 201 showed that the execution and successful completion of `notepad.exe` through the scheduled task `UpdateService`.This activity has detailed how scheduled tasks are used as a persistence mechanism.

## 6. Threat Hunting Summary
The PowerShell threat-hunting queries helped identify suspicious activity across different stages of the simulated attack. By connecting failed logon attempts, account creation, privilege changes, and scheduled-task execution, the events were correlated to understand the sequence of activity throughout the investigation.
