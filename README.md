# Enterprise-Windows-Threat-Hunting-And-Detection
## 1. Project Overview
This project simulates a multi-stage Windows attack in a controlled Windows 11 environment and investigates the activity from a SOC analyst's perspective.

The attack scenario includes:

- Repeated failed and successful login attempts
- System reconnaissance using PowerShell
- Unauthorized local account creation
- Privilege escalation
- Persistence through a scheduled task

Windows Event Viewer and PowerShell were used to analyze security events, correlate activity across the attack stages, and reconstruct the incident timeline. The project also includes PowerShell threat-hunting queries, detection logic, MITRE ATT&CK mapping, remediation recommendations, and a SOC-style incident report.

## 2. Project Objectives
- Simulate a multi-stage Windows attack in a controlled environment.
- Investigate authentication activity using Windows Security Event IDs.
- Analye post-compromise reconnaissance through process creation logs.
- Detect unauthorized account creation and administrative privilege changes.
- Identify and investigate persistence through a scheduled task.
- Using PowerShell queries to hunt for suspicious activity across Windows logs.
- Correlate security events to reconstruct the attack timeline.
- Map the observed activity to the MITRE ATT&CK framework.
- Develop detection and remediation recommendations from a SOC analyst perspective.

## 3. Lab Environment 
- Host system: macOS
- Virtualization : UTM
- Operating System : Windows 11
- Log Sources : Windows Security Logs and Task Scheduler Operational Logs
- Investigation Tools : Windows Event Viewer, Command Prompt, Windows PowerShell and Task Scheduler

## 4. Attack and Investigation Methodology
- Simulated failed and successful authentication attempts and investigated Windows Security Events 4625 and 4624.
- Performed system reconnaissance and analyzed process creation activity using Event ID 4688.
- Simulated unauthorized account creation and privilege escalation using a local `helpdesk` account.
- Investigated Event IDs 4720 and 4732 to identify account creation and administrative group membership changes.
- Simulated persistence by creating an `UpdateService` scheduled task and analyzed Task Scheduler Event IDs 200 and 201.
- Used PowerShell threat-hunting queries to correlate activity and reconstruct the attack timeline.
- Mapped the findings to MITRE ATT&CK and developed detection and remediation recommendations.

## 5. Phase 1: Lab Setup and Audit Configuration
### Objective
To configure and verify Windows auditing to capture the security events required for the investigation.
### Audit Configuration 
The Process Creation auditing was enabled to capture newly executed processes and generate event ID 4688.Command-line process auditing was also done to provide visibility into commands executed during the reconnaissance phase.
### Commands Used 
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable 
auditpol /get /subcategory:"Process Creation"
```
## 6. Phase 2: Authentication Attack Investigation 
### Objective 
To investigate the failed and successful logon attempts and to identify suspicious logon attempts using Windows Event Viewer.
### Investigation 
During the investigation , it was found that multiple incorrect passwords were intentionally entered for the local account `attacker` to simulate repeated failed logon attempts.
Windows Security Event IDs 4625 and 4624 were analyzed to detect failed and successful attempts relevant to timestamp,Task Category,logon type and target account.
### Events Investigated 
- **Event ID 4625 - Failed logon:** Captured failure logon authentication attempts of the local account `attacker`.
- **Event ID 4624 - Successful logon:** Captured successful logon authentication attempts after valid credentials has been entered.
### Key Findings 
- Multiple logon authentication attempts had been observed for the local account `attacker`.
- The failed attempts were followed by successful logon attempts using valid credentials.
- The whole sequence has a pattern that could potentially indicate a bruteforce Attack as there were repeated password attempts.
- Timestamps played a pivotal role of correlating failed and successful authentication attempts

## 7.Phase 3: PowerShell Reconnaissance and Process Analysis 
### Objective 
To investigate PowerShell System reconnaissance activity performed through Windows commands and Event viewer and to identify process creation events 
### Investigation
System reconnaissance was performed using Windows commands such as `whoami`,'ipconfig',`hostname` and `systeminfo` to collect information of the current user,system name,operating system and its network configuration.
Investigated Windows Security Event ID 4688 which were analyzed to identify the execution of the commands and examine such as process name,creator process,timestamp.
### Events Investigated 
- **Event ID 4688 - Process Creation** : Recorded the creation of new processes relevant with the reconnaissance commands
### Key Findings 
- Multiple powershell system reconnaissance commands are executed to collect information of the Windows host.
- Security Event ID 4688 provided its visibility into the processes created during the reconnaisance activity.
- The event timestamps help in correlating the command execution with the other stages of simulated attack.
- If the commands had been executed individually they would be legitimate but since multiple commands executed altogether it might indicate suspicious discovery activity.

## 8.Phase 4: Unauthorized Account Creation Investigation 
### Objective 
To investigate the creation of an unauthorized local account and to identify the account responsible for the action.
### Investigation 
A local user account `helpdesk' was created to simulate unauthorized account creation.Windows Security Event ID 4720 was analyzed to find the newly created account,the account responsible for the action and the timestamp.
### Event Investigated 
- **Event ID 4720 - Unauthorized User Account Created** : Recorded the creation of the local user account `helpdesk`.
### Key Findings
- A new local account named `helpdesk` has been successfully created.
- Event ID 4720 identified the account which is responsible for creating the new user.
- Unauthorized account creation would provide an attacker with continued access back to the compromised account.
- The timestamp of the event correlates the account creation with the surrounded attack activity.

## 9. Phase 5: Privilege Escalation Investigation 
### Objective 
To investigate the `helpdesk` account to the local Administrators group access and its unauthorized privilege access.
### Investigation 
The local account `helpdesk` was added to the built-in Administrators group to simulate privilige escalation .Windows Security Event ID 4732 was analyzed to identify the account performing the action ,the account which was added to the group and its affected security group.
### Event Investigated 
- **Event ID 4732 - Member added to a Security-Enabled Local Group** : Recorded the account `helpdesk` addition to the local Administrators group.
### Key Findings 
- The `helpdesk` account was added successfully to the local Administrators group .
- Event ID 4732 confirmed the administrative privileges access was granted to the `helpdesk` account.
- The membership elevated the access to system resources and its security settings.
- Unauthorized and unexpected changes to priviliged groups should be treated as high priority activity in a security investigation.

## 10.Phase 6: Scheduled Task Persistence Investigation 
### Objective 
To investigate persistence which was established through Windows Task Scheduler and verify it through Operational logs.
### Investigation 
While Investigating , a scheduled task named `UpdateService` was created to execute the `notepad.exe` at user logon,simulating persistence through the Windows Task Scheduler.
The task scheduler configuration was examined and Operational Event IDs 200 and 201 were analyzed to verify that the configured action was launched and successfully completed.
### Events Investigated 
- **Task Scheduler Event ID 200 - Action Started** : Captured the execution of `notepad.exe` by `UpdateService` scheduled task.
- **Task Scheduler Event ID 201 - Action Completed** : Confirmed that the scheduled task action successfully completed.
### Key Findings 
- The scheduled task `UpdateService` was configured for execution of `notepad.exe` at user logon.
- Security Event ID 200 confirmed that the scheduled task action has started or launched the action.
- Security Event ID 201 confirmed that the scheduled task action has completed or verified its successful compeletion.
- The task executable and the timestamps provided the evidence for correlating activity with its attack timeline.
