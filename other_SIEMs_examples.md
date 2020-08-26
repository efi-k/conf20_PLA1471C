**Windows Event – XML schema**

This is what the TA_Win expects (if not directly from a UF)

```<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'
Guid='{12345678-1234-1234-abcd-123456789012}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12345</Task><Opcode>0</Opcode><Keywords>0x0000000000000000</Keywords><Tim
eCreated SystemTime='2000-01-01T08:00:00.1234567890Z'/><EventRecordID>1234567</EventRecordID><Correlation ActivityID='{12345678-abcd-0000-1234-1234567890123}'/><Execution 
ProcessID='123' ThreadID='12345'/><Channel>Security</Channel><Computer>a-abcd.acme.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>NULL SID</Data><Data 
Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>NT AUTHORITY\ANONYMOUS LOGON</Data><Data 
Name='TargetUserName'>ANONYMOUS LOGON</Data><Data Name='TargetDomainName'>NT AUTHORITY</Data><Data Name='TargetLogonId'>0x1234567890</Data><Data Name='LogonType'>3</Data><Data 
Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>a-abcd</Data><Data 
Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>NTLM V1</Data><Data Name='KeyLength'>123</Data><Data 
Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>192.168.0.1</Data><Data Name='IpPort'>12345</Data><Data Name='ImpersonationLevel'>%%1234</Data><Data 
Name='RestrictedAdminMode'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1234</Data><Data 
Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1234</Data></EventData></Event>```


w