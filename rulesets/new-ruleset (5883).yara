/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: aroman
    Rule name: New Ruleset
    Rule id: 5883
    Created at: 2019-09-04 09:40:17
    Updated at: 2019-09-04 09:41:57
    
    Rating: #0
    Total detections: 4263
*/

import "androguard"


rule fakeapps009
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"


	condition:

		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81")

}
