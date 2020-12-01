/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Proxy3
    Rule id: 1647
    Created at: 2016-07-19 13:03:13
    Updated at: 2016-07-19 13:04:19
    
    Rating: #0
    Total detections: 3631
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "HELLO"
		$b = "PONG"
		$c = "SLEEP"
		$d = "WAIT"
		$e = "CREATE"
		$f = "HELLO\n"

	condition:
		all of them
		
}
