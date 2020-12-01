/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: orenk
    Rule name: emulator phone number
    Rule id: 2621
    Created at: 2017-05-04 07:18:54
    Updated at: 2017-05-04 07:19:43
    
    Rating: #0
    Total detections: 45064
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
		$a = /155552155(54|56|58|60|62|66|64|68|70|72)/

	condition:
		$a
	
		
}
