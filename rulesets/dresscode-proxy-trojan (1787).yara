/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: vtest
    Rule name: DressCode Proxy Trojan
    Rule id: 1787
    Created at: 2016-09-01 21:33:59
    Updated at: 2016-09-02 17:12:07
    
    Rating: #4
    Total detections: 1588
*/

import "androguard"

rule dresscode : trojan
{
    meta:
        description = "DressCode proxy bot: http://blog.checkpoint.com/2016/08/31/dresscode-android-malware-discovered-on-google-play/"

    strings:
	  $a = "REQUEST_CREATE"
	  $b = "REQUEST_HELLO"
	  $c = "REQUEST_PING"
	  $d = "REQUEST_SLEEP"
	  $e = "REQUEST_WAIT"
	  $f = "RESPONSE_HELLO"
	  $g = "RESPONSE_PONG"


    condition:
        ($a and $b and $c and $d and $e and $f and $g) or 
        (androguard.service(/com\.a\.c\.Service/) and androguard.receiver(/com\.a\.c\.Receiver/))
}
