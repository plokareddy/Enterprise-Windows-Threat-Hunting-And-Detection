# Detection Rules
## Overview
This section defines detection logic based on the suspicious activity observed during the Windows threat-hunting investigation. The detections focus on repeated authentication failures, unauthorized account creation, privileged group membership changes, and scheduled-task persistence.

## Detection 1: Repeated Failed Logon Attempts
### Event Source
Windows Security Log
### Event ID
4625
### Detection Logic
Generate an alert when multiple failed authentication attempts are recorded for the same target account within a short period of time.
### Example Threshold
Five or more failed authentication attempts against the same account within five minutes.
### Severity
Medium
### Rationale
Repeated failed authentication attempts may indicate password guessing or brute-force activity. The alert should be correlated with Event ID 4624 to determine whether the failures were followed by successful authentication.

## Detection 2: New Local Account Creation
### Event Source
Windows Security Log
### Event ID
4720
### Detection Logic
Generate an alert when a new local user account is created, particularly when the activity is unexpected or performed outside approved administrative processes.
### Severity
Medium
### Rationale
Attackers may create additional local accounts to maintain access to a compromised system.

## Detection 3: Account Added to Local Administrators Group
### Event Source
Windows Security Log
### Event ID
4732
### Detection Logic
Generate a high-priority alert when an account is added to the local Administrators group without an approved administrative change.
### Severity
High
### Rationale
Unexpected changes to privileged group membership may indicate privilege escalation or an attempt to obtain elevated access.

## Detection 4: Suspicious Scheduled-Task Execution
### Event Source
Task Scheduler Operational Log
### Event IDs
200 and 201
### Detection Logic
Identify scheduled tasks executing unexpected programs or binaries, particularly tasks with unusual names, execution paths, or logon-based triggers.
### Severity
High
### Rationale
Attackers can abuse scheduled tasks to execute malicious code automatically and maintain persistence on a compromised system.
