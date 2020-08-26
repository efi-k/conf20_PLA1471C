-----------------------------------------------------
**You can do some nice thing with calculated fields**
-----------------------------------------------------

- The objective:  If the string action is null, put “unkown”, otherwise replace: “,” with ”|”  , “Notify” with “NTFY”, “Monitor” with “Mon”, “Block” with “BL”

if(isnull(action),"unknown",replace(replace(replace(replace(action,"Notify","NTFY"),"Monitor","MON"),"Block","BL"),",","|"))

"Notify,Block“  =>  NTFY|BL


- Cleaning up domain and workgroup from user fields:  acme\\jdoe => jdoe

replace(user ,".*\\\\","") 


- If dst is an IP put it in dest_ip otherwise put it in dest

if(match(dst,"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"),dest,dest_ip)

If needed to extract CEF from within a NON-CEF event use external transformation in field extraction cefHeaders and cefKeys

Refer to CEF extraction addon by Igor Sher https://splunkbase.splunk.com/app/487
