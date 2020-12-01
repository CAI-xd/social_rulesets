/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Aadhaar VID Generator Tracker
    Rule id: 5168
    Created at: 2018-12-27 11:45:22
    Updated at: 2018-12-27 11:48:11
    
    Rating: #0
    Total detections: 36
*/

import "androguard"

rule aadhaar_vid_generators
{
	meta:
		description = "This rule detects Aadhaar VID Generation in apps"
	strings:
		$a = "https://resident.uidai.gov.in/web/resident/vidgeneration"
		$b = "https://resident.uidai.gov.in/vidgeneration"		
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)		
}
