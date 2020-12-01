/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: OpenSSL
    Rule id: 6213
    Created at: 2019-12-14 18:52:41
    Updated at: 2019-12-15 17:27:29
    
    Rating: #0
    Total detections: 943
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
		$ = "OpenSSL 1.0.1"
		$ = "OpenSSL 1.0.0"

	condition:
		any of them
		
}
