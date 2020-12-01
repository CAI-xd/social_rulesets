/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ElTrampero
    Rule name: GuiaSitio
    Rule id: 1398
    Created at: 2016-05-17 10:43:42
    Updated at: 2016-05-17 10:44:58
    
    Rating: #0
    Total detections: 32
*/

import "androguard"
import "file"
import "cuckoo"


rule guiasitio : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"


	condition:
		androguard.url(/guiasitio\.com.*/)
		
}
