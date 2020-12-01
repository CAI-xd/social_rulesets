/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Load2ing
    Rule name: New Ruleset
    Rule id: 4293
    Created at: 2018-03-27 05:54:34
    Updated at: 2018-04-03 05:54:39
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Fake korea Banker"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "kkk.kakatt.net:3369/send_pro"

	condition:
		$a
		
}
