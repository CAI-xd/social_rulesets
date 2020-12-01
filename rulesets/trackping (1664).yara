/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: TrackPing
    Rule id: 1664
    Created at: 2016-07-21 12:30:44
    Updated at: 2016-07-21 12:31:02
    
    Rating: #0
    Total detections: 2023
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
		$a = "Yeahmobi_Trackping"

	condition:
		all of them
		
}
