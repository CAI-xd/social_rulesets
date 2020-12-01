/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: xposed Detection
    Rule id: 3894
    Created at: 2017-12-10 00:35:47
    Updated at: 2017-12-10 00:36:01
    
    Rating: #0
    Total detections: 370
*/

import "androguard"
import "file"
import "cuckoo"

rule xposed : anti_hooking
{
	meta:
		description = "Xposed"
		info        = "xxxxxxx"
		example     = ""

	strings:
		$a = "xposed"
		$b = "rovo89"

	condition:
		all of them
}
