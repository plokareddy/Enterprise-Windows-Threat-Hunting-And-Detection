# SOC Incident Report
## Incident Summary
A multi-stage Windows attack was simulated in a controlled Windows 11 environment to investigate authentication activity, system reconnaissance, unauthorized account creation, privilege escalation, and scheduled-task persistence.
Windows Event Viewer and PowerShell were used to analyze and correlate events across the simulated attack lifecycle.

## Incident Classification
- **Incident Type:** Simulated Multi-Stage Windows Attack
- **Environment:** Controlled Windows 11 Lab
- **Overall Severity:** High
- **Status:** Investigation Completed

## Attack Timeline
| Stage | Activity | Event ID / Log Source |
|---|---|---|
| Authentication | Repeated failed logon attempts | 4625 |
| Authentication | Successful logon | 4624 |
| Reconnaissance | System discovery commands executed | 4688 |
| Account Creation | Local `helpdesk` account created | 4720 |
| Privilege Escalation | `helpdesk` added to Administrators group | 4732 |
| Persistence | `UpdateService` scheduled task executed `notepad.exe` | Task Scheduler 200 and 201 |

## Investigation Findings
The investigation identified repeated failed authentication attempts followed by successful authentication. System reconnaissance commands were then executed to gather information about the user, hostname, operating system, and network configuration.
A new local account named `helpdesk` was created and subsequently added to the local Administrators group, granting it elevated privileges. A scheduled task named `UpdateService` was also configured to execute `notepad.exe` at user logon, simulating persistence.
Event timestamps and account information were correlated to reconstruct the sequence of activity.

## Impact Assessment
If this activity occurred in a production environment, it could indicate unauthorized access followed by reconnaissance, account creation, privilege escalation, and persistence. An attacker with administrative privileges and a persistent execution mechanism could maintain continued access and perform additional malicious actions.

## Recommended Actions
- Investigate repeated failed logon attempts and determine their source.
- Reset credentials for potentially compromised accounts.
- Review newly created local accounts and remove unauthorized accounts.
- Audit membership changes to privileged groups.
- Review scheduled tasks for unexpected names, triggers, or executables.
- Enable centralized log collection and alerting for relevant Windows events.
- Correlate failed and successful authentication events to detect potential account compromise.

## Conclusion
The investigation demonstrated how multiple Windows events can be correlated to reconstruct a multi-stage attack sequence. Authentication events, process creation logs, account-management events, privilege changes, and Task Scheduler telemetry provided visibility into different stages of the simulated attack.
The project highlights the importance of event correlation, timestamp analysis, and threat hunting in identifying suspicious activity and supporting incident investigation.
