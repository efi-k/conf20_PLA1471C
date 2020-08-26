--------------------------------------------------
**Using heavy forwarders to filter and tame data**
--------------------------------------------------


- Qradar JSON adjustment:

props.conf

SEDCMD-removeprefix = s/\<\d+\>\-[^{]+//g
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = \”\}




- Check for the time of the event vs the time of the SIEM:

Props.conf:

DATETIME_CONFIG, MAX_TIMESTAMP_LOOKAHEAD, TIME_FORMAT



-  Remove description:

Props.conf ->

TRANSFORMS-removedescription = removedesc

TRANSFORMS.conf ->

[removedesc]
LOOKAHEAD = 16128
REGEX = (?msi)(.*)(This event is generated.8?)(\”\,\”.*)
FORMAT = $1$3
DEST_KEY = _raw




- Force CEF Events sourcetype:

transforms.conf

REGEX = CEF\:0|McAfee\|ESM\|
DEST_KEY = Metadata:sourcetype
FORMAT = sourcetype::cefevents




- Redirect to index

[redirect mcafee]

REGEX = deviceExternalId\=Mcafee\sCorrelation\sEngine
DEST_KEY = _Metadata:Index
FORMAT = acmesiem
