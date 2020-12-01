/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lucschouten
    Rule name: YARA rule assignment 2, apk2
    Rule id: 7288
    Created at: 2020-11-12 19:38:11
    Updated at: 2020-11-12 20:12:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule spyware {
	meta:
		description = "This rule detects similar applications like the Save Me spyware application that can make phone calls"
		sample = "Save Me"
		author = "Luc Schouten & Dylan macquine"
		date = "12-11-2020"
		
	strings:
		$string1 = "sendTextMessage"
		
	condition:
	(androguard.service(/CHECKUPD/) and androguard.service(/GTSTSR/) and androguard.url("http://xxxxmarketing.com") and androguard.url("http://topemarketing.com/app.html") and $string1)

}
