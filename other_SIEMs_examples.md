------------------------------
**Windows Event – XML schema**
------------------------------

- This is what the TA_Win expects (if not directly from a UF)

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'
Guid='{12345678-1234-1234-abcd-123456789012}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12345</Task><Opcode>0</Opcode><Keywords>0x0000000000000000</Keywords><TimeCreated SystemTime='2000-01-01T08:00:00.1234567890Z'/><EventRecordID>1234567</EventRecordID><Correlation ActivityID=
'{12345678-abcd-0000-1234-1234567890123}'/><Execution ProcessID='123' ThreadID='12345'/><Channel>Security</Channel><Computer>a-abcd.acme.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>NULL SID</Data><Data 
Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>NT AUTHORITY\ANONYMOUS LOGON</Data><Data 
Name='TargetUserName'>ANONYMOUS LOGON</Data><Data Name='TargetDomainName'>NT AUTHORITY</Data><Data Name='TargetLogonId'>0x1234567890</Data><Data Name='LogonType'>3</Data><Data 
Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>a-abcd</Data><Data 
Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>NTLM V1</Data><Data Name='KeyLength'>123</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>192.168.0.1</Data><Data Name='IpPort'>12345</Data><Data Name='ImpersonationLevel'>%%1234</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1234</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1234</Data></EventData></Event>
```

------------
***Qradar***
------------

- MUCH easier to work with the JSON format (refer to https://github.com/efi-k/conf20_PLA1471C/blob/master/Other_SIEMs.md about how to switch)

- Syslog

<13>jan 01 08:00:00 192.168.1.1 AgentDevice=WindowsLog\tAgentLogFile=Security\tSource=Microsoft-Windows-Security-Auditing\tComputer=abcd.abc.local\tUser=\tDomain=\tEventID=4624\tEventIDCode=4624\tEventType=8\tEventCategory=12345\tRecordNumber=123456789\tTimeGenerated=1234567890123\tTimeWritten=1234567890123\tMessage=An account was successfully logged on. Subject: Security ID: S-0-0-0 Account Name: - Account Domain: - Logon ID: 0x0 Logon Type: 3 New Logon: Security ID: S-0-0-12-12345678-12345678-123456789-1234 Account Name: abcdefg$ Account Domain: abc Logon ID: 0xabcd0000 Logon GUID: abcd000-0000-abcd-1234-123456789 Process Information: Process ID: 0x0 Process Name: - Network Information: Workstation Name: Source Network Address: 192.168.1.1 Source Port: 1234 Detailed Authentication Information: Logon Process: Kerberos Authentication Package: Kerberos Transited Services: - Package Name (NTLM only): - Key Length: 0

- JSON

{"name":"DefaultProfile","version":"1.0","isoTimeFormat":"yyyy-MM-dd'T'HH:mm:ss.SSSZ","type":"Event","category":"4624","protocolID":"123","sev":"1","src":"192.168.0.1","dst":"192.168.1.2","srcPort":"1234","dstPort":"0","relevance":"1","credibility":"1","startTimeEpoch":"1234567890123","startTimeISO":"2000-01-01T08:00:00.000+00:00","storageTimeEpoch":"1234567890123","storageTimeISO":"2000-01-01T08:00:00.000+00:00","deploymentID":"1234abcd-1234-1234-abcd-123456789012","devTimeEpoch":"1234567890123","devTimeISO":"2000-01-01T08:00:00.000+00:00","srcPreNATPort":"0","dstPreNATPort":"0","srcPostNATPort":"0","dstPostNATPort":"0","hasIdentity":"false","payload":"<13>jan 01 08:00:00 192.168.1.1 AgentDevice=WindowsLog\tAgentLogFile=Security\tSource=Microsoft-Windows-Security-Auditing\tComputer=abcd.abc.local\tUser=\tDomain=\tEventID=4624\tEventIDCode=4624\tEventType=8\tEventCategory=12345\tRecordNumber=123456789\tTimeGenerated=1234567890123\tTimeWritten=1234567890123\tMessage=An account was successfully logged on. Subject: Security ID: S-0-0-0 Account Name: - Account Domain: - Logon ID: 0x0 Logon Type: 3 New Logon: Security ID: S-0-0-12-12345678-12345678-123456789-1234 Account Name: abcdefg$ Account Domain: abc Logon ID: 0xabcd0000 Logon GUID: abcd000-0000-abcd-1234-123456789 Process Information: Process ID: 0x0 Process Name: - Network Information: Workstation Name: Source Network Address: 192.168.1.1 Source Port: 1234 Detailed Authentication Information: Logon Process: Kerberos Authentication Package: Kerberos Transited Services: - Package Name (NTLM only): - Key Length: 0 " ,"eventCnt":"1","hasOffense":"false","domainID":"1","domainName":"AB","eventName":"Success Audit: An account was successfully logged on","lowLevelCategory":"User Login Success","highLevelCategory":"Authentication","eventDescription":"Success Audit: An account was successfully logged on.","logSource":"WindowsAuthServer @ 192.168.1.1","srcNetName":"other","dstNetName":"other","logSourceType":"Microsoft Windows Security Event Log","logSourceGroup":"AB Qradar","logSourceIdentifier":"192.168.1.1","AccountName":"-"}


-------------
**Archsight**
-------------

- CEF : A header containing product and vendor details, separated by a pipeline followed by key-value pairs. Can be easily extract using the “CEF Extraction Add-on for Splunk” on Splunkbase

CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:4624|An account was successfully logged on.|Low| eventId=123456 externalId=4624 msg=Network: A user or computer logged on to this computer from the network. categorySignificance=/Informational categoryBehavior=/Authentication/Verify categoryDeviceGroup=/Operating System catdt=Operating System categoryOutcome=/Success categoryObject=/Host/Operating System art=1234567890123 cat=Security deviceSeverity=Audit_success rt=1234567890123 src=192.168.1.1 sourceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 spt=12345 dhost=abcdef.abc.local dntdom=abc duser=abcde$ duid=0xabcd1234 dproc=- oldFileHash=en_US|UTF-8 cs1=Impersonation cs2=Logon cs3=0x0 cs5=Kerberos cs6={12345-1234-abcd-1234-12345678} cn1=3 c6a4=ab00:0:0:0:1234:1234:0000:abcd cs1Label=Impersonation Level cs2Label=EventlogCategory cs3Label=Process ID cs4Label=Restricted Admin Mode cs5Label=Authentication Package Name cs6Label=Logon GUID cn1Label=Logon Type c6a4Label=Agent IPv6 Address ahost=abcd.efgh.local agt=1.1.1.1 agentZoneURI=/All Zones/ArcSight System/Public Address Space Zones/ATT Bell Laboratories av=1.1.1.1234.0 atz=Asia/Jerusalem aid=abcde+12345\=\= at=syslog dvchost=abcd.abc.local deviceNtDomain=- dtz=Asia/Jerusalem deviceProcessName=Kerberos _cefVer=0.1 ad.TargetUserSid=NT AUTHORITY\\\\SYSTEM ad.KeyLength=0 ad.SubjectUserSid=NULL SID ad.LmPackageName=- ad.SubjectUserName=- ad.TransmittedServices=- ad.ProcessID=123 ad.Version=1 ad.WorkstationName= ad.ThreadID=1234 ad.SubjectLogonId=0x0 ad.geid=0 ad.Opcode=Info ad.EventRecordID=12345678

----------------
**McAfee ESM**
----------------

- Default

Jan 1 08:00:00 192.168.0.1 2000-01-01T08:00:00.0+00:00 1.2.3.4 McAfee_SIEM: 43-263046240;An account was successfully logged on;192.168.0.1;192.168.0.2;4624;0;00:00:00:00:00:00;00:00:00:00:00:00;0;0;0;3;1234567890;1234567890;0;success;12;123456789;123456789;12345678901234567;abcdef-ab1:192.168.1.2;43

- Need to make sure that ESM will pass the keys together with the values (see https://github.com/efi-k/conf20_PLA1471C/blob/master/Other_SIEMs.md)

Jan 1 08:00:00 192.168.0.1 2000-01-01T08:00:00.000+00:00 1.2.3.4 CEF:0|McAfee|ESM|1.2.3|43-263046240|An account was successfully logged on|2|start=1234567890123 end=1234567890123 rt=1234567890123 cnt=1 eventId=123456789 nitroUniqueId=123456789 deviceExternalId=abcdef-ab1 deviceTranslatedAddress=192.168.1.2 externalId=123456789 cat=Host Login nitroNormID=123456789 act=success deviceDirection=0 dst=192.168.1.2 src=192.168.1.1 spt=12345 nitroTrust=2 nitroAppID=kerberos sntdom=abcdef shost=abcdef-ab1.abcdef.local suser=Administrator nitroSecurity_ID=S-1-2-3-1234567890-1234567890-123456789-123 nitroLogon_Type=3 - Network nitroSource_Logon_ID=0x0 nitroDestination_Logon_ID=0x123456789

----------
**Syslog**
----------

- The least preferred way

<13>Original Address=192.168.1.1 Jan 01 08:00:00 abcd123 AgentDevice=WindowsLog AgentLogFile=Security Source=Microsoft-Windows-Security-Auditing Computer=abcd123.abcd.LOCAL User= Domain= EventID=4624 EventIDCode=4624 EventType=8 EventCategory=12345 RecordNumber=12345678 TimeGenerated=1234567890123 TimeWritten=1234567890123 Message=An account was successfully logged on. Subject: Security ID: NULL SID Account Name: - Account Domain: - Logon ID: 0x0 Logon Information: Logon Type: 3 Restricted Admin Mode: - Virtual Account: No Elevated Token: No Impersonation Level: Impersonation New Logon: Security ID: abcd\efgh$ Account Name: abcde$ Account Domain: abcd.local Logon ID: 0xd12345678 Linked Logon ID: 0x0 Network Account Name: - Network Account Domain: - Logon GUID: 12345-1234-abcd-1234-12345678 Process Information: Process ID: 0x0 Process Name: - Network Information: Workstation Name: Source Network Address: 192.168.1.1 Source Port: 12345 Detailed Authentication Information: Logon Process: Kerberos Authentication Package: Kerberos Transited Services: - Package Name (NTLM only): - Key Length: 0 


