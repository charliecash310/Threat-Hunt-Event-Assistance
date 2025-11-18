# Threat Hunt Scenario - Assistance

<img width="647" height="551" alt="image" src="https://github.com/user-attachments/assets/3dbc54c7-3132-4ed4-8601-b339dcc1483f" />

# Table of Contents

Detection and Analysis:
- [Flag 1 - Initial Execution Detection]() 
- [Flag 2 - Defense Disabling]()
- [Flag 3 - Quick Data Probe]()
- [Flag 4 - Host Context Recon]()
- [Flag 5 - Storage Surface Mapping]()
- [Flag 6 - Connectivity & Name Resolution Check]()
- [Flag 7 - Interactive Session Discovery]()
- [Flag 8 - Runtime Application Inventory]()
- [Flag 9 - Privilege Surface Check]()
- [Flag 10 - Proof-of-Access & Egress Validation]()
- [Flag 11 - Bundling / Staging Artifacts]()
- [Flag 12 - Outbound Transfer Attempt]()
- [Flag 13 - Scheduled Re-Execution Persistence]()
- [Flag 14 - Autorun Fallback Persistence]()
- [Flag 15 - Planted Narrative / Cover Artifact]()
- [Logical Flow & Analyst Reasoning]()
- [Final Notes / Findings]()

MITRE ATT&CK Framework:
- [Flags → MITRE ATT&CK Mapping Table]()
- [Summary of ATT&CK Categories Used]()

Lessons Learned:
- [🔒 1. Strengthen PowerShell Logging & Restrictions]()
- [📁 2. Restrict Execution from User Download Folders]()
- [🔍 3. Harden Scheduled Task Abuse]()
- [🚫 4. Prevent Registry Run Key Persistence]()
- [🌐 5. Improve Network Egress Controls]()
- [🛡 6. Enable/Improve Endpoint Security Controls]()
- [🧩 7. Block Living-off-the-Land Binaries (LOLBins)]()
- [🔐 8. Least Privilege Enforcement]()
- [📦 9. User Education & Phishing Awareness]()
- [🧵 10. Improve SOC Detection Logic]()
- [🗂 11. File System Hardening]()


---
# Report By

`**Date:** October 1st - 15th, 2025`  
`**Analyst:** Grisham DelRosario`  
`**Environment:** Microsoft - Log Analytics Workspace (LAW - Cyber Range)`  
`**Attack Type:** Fake Remote Session/Malicious Help Desk` 

---------------
# **Scenario**

`A routine support request should have ended with a reset and reassurance. Instead, the so- called "help" left behind a trail of anomalies that don't add up. What was framed as troubleshooting looked more like an audit of the system itself probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended. And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny. This wasn't remote assistance. It was a misdirection. Your mission this time is to reconstruct the timeline, connect the scattered remnants of  this "support session", and decide what was legitimate, and what was staged. The evidence is here. The question is whether you'll see through the story or believe it.`

---------------------------------------------------
# **Preparation**

<img width="657" height="309" alt="image" src="https://github.com/user-attachments/assets/8942b8bf-b907-47bc-9334-ea9f6ffc6f16" />

<img width="655" height="151" alt="image" src="https://github.com/user-attachments/assets/a763f5e7-4426-4ee3-b02f-beaa98be81a5" />

<img width="715" height="199" alt="image" src="https://github.com/user-attachments/assets/c1dce20f-a108-4b62-a762-2682c38e28e3" />

---

1. Spawning process originating from the download folder. Occurred in the first half of October, so sometime between October 1st -15th?

2. Similar executables, naming patterns, and other traits.

3. Common keywords, `"desk", "help", "support", and "tool"`


<img width="1450" height="575" alt="image" src="https://github.com/user-attachments/assets/f0c6c24a-97fd-4884-8613-8c23a803a964" />

In order to identify the most suspicious machine based on the given conditions I decided to set a variable called 'keywords' with "desk", "help", "support", and "tool" in order to set up the query. 

First table I checked to start this hunt was 'DeviceFileEvents.' 

The keyword "support" also allowed me to find this suspicious filename, " Support_701.txt " that was unusual as I was going through the logs but it allowed me to find the suspicious machine. I kept focus as it was mentioned at starting point 

several machines were found to share the same types of files - similar executables, naming patterns, and other traits - 


<img width="2290" height="297" alt="image" src="https://github.com/user-attachments/assets/0585de67-d225-484e-a828-906771a4a5cc" />


Ideally, another way I could have found this device without having to think so hard was to have queried the term `Intern` for `DeviceName` in order to find the suspicious device, 

`gab-intern-vm`

This too would have been an easier method to find in order to narrow down the suspicious device.




---------------------------------------------------
# **Detection and Analysis**

# Flag 1 - Initial Execution Detection



Throughout the threat hunt, the table `'DeviceProcessEvents'` was very key in order to examine the logs.

For Flag 1, we're looking at Initial Execution Detection

When I read what to hunt and saw 'script', the first thing that came to mind was PowerShell and Command Prompt.

Further on, the question asked 

`"What was the first CLI (command line interface) parameter name used during the execution of the suspicious program?"`

After looking back and forth at was being asked of the flag and examining logs `"unusual execution"` was key in order to find this flag.

The earliest anomalous execution of powershell being executed was October 9th, 2025 @ 12:22 PM





Upon looking at the log activity for powershell executables we can see the first CLI parameter is set to `-ExecutionPolicy`.  First time it was executed was on October 6th, 2025 at 6:00:48 AM

This eventually occurred again for a powershell.exe process called `SupportTool.ps1` 
for October 9th, 2025 during 12:22:27 PM UTC


---------------------------------------------------

# Flag 2 - Defense Disabling




----------------------------------------------------------------------

Further on, I decided to pivot back into `DeviceProcessEvents` table and look back into more power shell activity.

I kept noticing this command scrolling through the logs and noticed the string when querying for  `Artifact` and `Out-File -FilePath 'C:\Users\Public\DefenderTamperArtifact.txt'`

The query used in Flag 1 to understand the CLI parameter `-ExecutionPolicy`, was key into understanding the timeline of events

that showed another powershell command outputting a file called 

`DefenderTamperArtifact.txt`

As I kept querying for the term artifact and I kept on encountering the file name 

`ReconArtifacts.zip.`

It was the closest thing I can find but it was not the official tampered artifact.

Still needed to find something related to either this or the `DefenderTamperArtifact.txt` file.

Somehow I knew these were related to Defense Disabling but could not make the linkage as to how it was all connected.







I decided to check `DeviceFileEvents` table and query for `Artifact` in the `FileName` column.





For the query, I kept using `Artifact` and used this information to see if there was another file name related to the term.

I found `ReconArtifacts.zip` and then saw that there was a 

`DefenderTamperArtifact.lnk` file. 

The timestamp matches with process creation from the `DeviceProcessEvents` table

The  `.lnk`  file extension is a shortcut of the filename. Upon researching `.LNK` files, they are often the trigger for malicious scripts and  can be used for malicious purposes.





---------------------------------------------------

# Flag 3 - Quick Data Probe



For this flag I imagined the command value had something to do with copy and paste actions as it is a common short-lived action.

The other part to this was the term `query`

I decided to check the `InitiateProcessCommandLine` column and find syntax and flags that looked like it was written as a query.

Upon looking I kept my focus on the timeline of the script and tried to match up the time .

The `InitiatingProcessCommandLine` showed this command below when querying for `'clip'`

The Answer:

`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null }    catch { }"` 


This specific activity related to `powershell` has the syntax for a query such as 

`"try { Get-Clipboard | Out-Null } catch { }"`






---------------------------------------------------

# Flag 4 - Host Context Recon



While going through the logs, and reading this flag I recall seeing an executable called ' qwinsta.exe ' I had to look up this program and it is a command on windows that can:

	'Display information about sessions on a Remote Desktop Session Host server'

This made sense in terms of gathering host and user context information.

Working within the timestamp of `2025-10-09T12:51:44.3425653Z` we can see that this was the last recon attempt for the query session for the attacker to enumerate.






---------------------------------------------------

# Flag 5 - Storage Surface Mapping



After looking at the 'qwinsta.exe' process that was created in the logs.

I noticed the command prompt executable that showed logical disk that comes after the 'qwinsta.exe' executable.

This made sense in terms of data as to where it lives and the data that can be discovered such as 'storage'. Decided to search for 'WMIC.exe' command and found out that the 'logical disk'

We can see the `TimeGenerated` column is still within 12:50:00 PM-12:51:00 PM.

	Time Generated @ 2025-10-09T12:51:18.3848072Z
	"cmd.exe" /c wmic logicaldisk get name,freespace,size






---------------------------------------------------

# Flag 6 - Connectivity & Name Resolution Check



What was key to this question was network related events. 
Especially when it comes to DNS and outbound connections.

I decided to check the `InitiatingProcessParentFileName` column in the `DeviceNetworkEvents` table and try to narrow down unusual PowerShell activity.

I made sure to stay focused on October 9th 2025 during the time of `12:50-12:55 PM` as other events from `DeviceProcessEvents` and `DeviceFileEvents` were very important in relation to `SupportToolScript.ps1`. `Powershell` executables have been very prevalent throughout the hunt. 






---------------------------------------------------

# Flag 7 - Interactive Session Discovery



`Keywords: Session, Initiate Process, Unique`

Had to get a little help with this one from another user without having to give away the answer and eventually I had a lightbulb moment.

It was actually really simple. When I read the question "What is the unique ID of the initiating process?" I kept focusing for the column `InitiatingProcessID`

I was so stumped that I feel the process identification task number was staring at me.  I had to pivot and got the hint from a user to project `InitiatingProcessUniqueId`

I should have considered the term `unique` in order to find the number of `InitiatingProcessUniqueId`

	2533274790397065










---------------------------------------------------

# Flag 8 - Runtime Application Inventory



They want the _file name_ of the process that shows:
- `“runtime process enumeration”
- `“process-list snapshots”
- `“queries of running services”

And the hint:
1. `Task
2. `List
3. `Last

This is pointing directly at:

 **`tasklist.exe`**






---------------------------------------------------

# Flag 9 - Privilege Surface Check



**Objective**
> Detect attempts to understand privileges available to the current actor.

This means: **we’re hunting for commands that ask “who am I?” or “what privileges do I have?”**

**What to Hunt**
> Queries of group membership, token properties, or privilege listings.

That’s `whoami` territory.

**Hint:**
1. Who

> **Identify the timestamp of the very first attempt.**
    The timestamp of the earliest privilege-checking event.

`TimeGenerated`
`2025-10-09T12:52:14.3135459Z`







---------------------------------------------------

# Flag 10 - Proof-of-Access & Egress Validation



Outbound Contact = Anything the host reaches OUT to

In other words:
- `DNS lookups
- `HTTP(S) requests
- `TCP/IP connections to external hosts
- `Ping / ICMP echo requests
- `Anything that leaves the VM and touches the internet or another host

Defender logs this as `DeviceNetworkEvents.`
	Decided to check the `RemoteUrl` column for outbound connections that were being tested with powershell.exe results below were the only existing domains to an unusual destination.





---------------------------------------------------

# Flag 11 - Bundling / Staging Artifacts



Dropped at: 

**`C:\Users\Public\ReconArtifacts.zip`**

And the logs confirm it perfectly:
- First created → **`12:58:17.436 PM`**, in _Public_
- Then copied or moved → _Documents_
- But they specifically ask for "first dropped", meaning the public directory.

Exactly the kind of staging behavior attackers love:

- `Public is world-writable
- `No elevation required
- `No user desktop pop-ups
- `Easy to exfiltrate quietly





---------------------------------------------------

# Flag 12 - Outbound Transfer Attempt





Recall the same query from Flag 10. The IP of the last unusual outbound connection was listed to a website called `httpbin.org` .

The `RemoteIP` column showed the IP, `100.29.147.161`, of the outbound connection





---------------------------------------------------

# Flag 13 - Scheduled Re-Execution Persistence



The question asks for `task name`





We can see in the output of `schtasks.exe` that the task name `/TN` flag is part of the process command line. 

We can see the value of the task name is `SupportToolUpdater`

---------------------------------------------------

# Flag 14 - Autorun Fallback Persistence



The table `RemoteAssistUpdater` returned nothing. 


---------------------------------------------------

# Flag 15 - Planted Narrative / Cover Artifact



The actor **left a cover story behind**, and the hint gives it away:

> **Hint:** The actor opened it for some reason.

That means we’re hunting for a file the attacker **manually opened**, likely something meant to _explain_ or _justify_ what they were doing. 

The attacker delivered `SupportTool.ps1` to the victim’s Downloads folder and then executed it via the Windows shell, causing Explorer to create `SupportTool.lnk` in the Recent items directory.

This ties the script to an interactive session (likely the `g4bri3Intern` profile) and demonstrates user-level execution (MITRE ATT&CK T1204 – User Execution).
