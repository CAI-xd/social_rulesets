/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: fortnite_appclone
    Rule id: 4622
    Created at: 2018-07-03 23:18:26
    Updated at: 2018-07-03 23:25:14
    
    Rating: #0
    Total detections: 1062
*/

import "androguard"
import "file"
import "cuckoo"


rule fortnite_appclone
{
	meta:
		description = "This rule detects new Fortnite malicious apps"
		sample = "2a1da7e17edaefc0468dbf25a0f60390"

	strings:
		$a_1 = "StealthMode"
		$a_2 = "onStartCommand"
		$a_3 = "ShowOnLockScreen"
		$a_4 = "The original WhatsApp"
		
		
	condition:
		all of ($a_*)
		
}
