/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: apitarresi
    Rule name: rule300
    Rule id: 4842
    Created at: 2018-08-23 17:44:51
    Updated at: 2018-08-23 17:47:56
    
    Rating: #0
    Total detections: 0
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
		$a = "BZWBK mobile"

	condition:
		androguard.package_name(/BZWBK/) or $a
		
}
