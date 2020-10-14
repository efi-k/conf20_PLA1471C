# How to make splunk heavy-forwarder reiterate over props.conf after changing the sourcetype with a transforms.conf


Since my .Conf20 session was already recorded, you might want to consider the below as an addendum since it is inline with the session topic and the motivation to spend hours finding a solution stem from the same problem statement: What to do if you have very little or no control over the data source ?

The background story

Recently I had to improve the data quality of a source that is feeding my splunk instance with various security events over a single port.

A major part of the process I'm usually following is breaking the events into different source types using regex. A fairly standard procedure up to this point.

However in this case, to make things worse, the events included a unique IDS log with a different time zone than my locale and without any identification in the time stamp so the splunk time interpreter took the time as it is without adjusting it to UTC.

So they say you can't reiterate props.conf...

Just adding the new IDS sourcetype stanza in props.conf wouldn't work because normally splunk goes once through the pipeline and wouldn't get back to the Typing pipeline after first changing the sourcetype key to the IDS key.

So here is the solution I've found to create a loopback that will make the IDS events go back through the pipeline and have the time zone properly adjusted.

The basic ideas is to have those IDS event, after being assigned with the proper sourcetype, go through the syslog routing where the server is... the forwarder itself,listening on another port. Then the IDS sourcetype stanza in the props.conf will do its thing and problem solved !


# inputs.conf

[default]
host=$decideOnStartup

\# This is the input to the original data source
[udp://3000]
connection_host = none
index = rawevents
sourcetype = mixedevents
disabled = false

\# This is the port created for the loopback
[udp://3100]
connection_host = none
index = rawevents
sourcetype = idsevents
disabled = false



# props.conf

\# Just like sourcetype name implies...
[mixedevents]
DATETIME_CONFIG = 
TIME_PREFIX = (Security\s+\d+|N\/A\s+\d+)
MAX_TIMESTAMP_LOOKAHEAD = 30
TRANSFORMS-raw = send_rawevents
TRANSFORMS-set_ids_sourcetype = set_ids
TRANSFORMS-ids_to_null_tcp = send_to_null_tcp
TRANSFORMS-ids_to_syslog = send_to_syslog

\# This stanza will work only for the second iteration
[idsevents]
DATETIME_CONFIG = 
TIME_PREFIX = \srt\=
MAX_TIMESTAMP_LOOKAHEAD = 30
TZ = UTC

# transforms.conf

[send_rawevents]
REGEX = ^((?!CEF\:0\|ids).)*$
DEST_KEY = _TCP_ROUTING
FORMAT = indexer1


[set_ids]
REGEX = CEF\:0\|ids
FORMAT = idsevents
DEST_KEY = MetaData:Sourcetype

\# to make sure that the IDS event will be indexed twice (TCP+SYSLOG routing)
[send_to_null_tcp]
REGEX = CEF\:0\|ids
DEST_KEY = _TCP_ROUTING
FORMAT = nothing


[send_to_syslog]
REGEX = CEF\:0\|ids
DEST_KEY = _SYSLOG_ROUTING
FORMAT = syslog_group

# outptus.conf

[syslog:syslog_group]
server = this_HF:3100
type = udp


[tcpout:indexer1]
server = my_indexer:4000


