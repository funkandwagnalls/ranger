# ranger
A tool to support security professionals access and interact with remote Microsoft Windows based systems.

This project was conceptualized with the thought process, we did not invent the bow or the arrow, 
just a more efficient way of using it.

Ranger is a command-line driven attack and penetration testing tool, which as the ability to use 
an instantiated catapult server to deliver capabilities against Windows Systems.  As long as a user 
has a set of credentials or a hash set (NTLM, LM, LM:NTLM) he or she can gain access to systems that 
are apart of the trust.

Using this capability a security professional can extract credentials out of memory in clear-text, 
access SAM tables, run commands, execute PowerShell scripts, Windows Binaries, and other tools.  
At this time the tool bypasses the majority of IPS vendor solutions unless they have been custom 
tuned to detect it. The tool was developed using our home labs in an effort to support security 
professionals doing legally and/or contractually supported activities.

More functionality is being added, but at this time the tool uses the community contributions 
from repositories related to the PowerShell PowerView, PowerShell Mimikatz and Impacket teams.  
