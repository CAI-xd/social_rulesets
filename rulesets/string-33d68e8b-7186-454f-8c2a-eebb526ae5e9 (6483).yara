/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: String = "33d68e8b-7186-454f-8c2a-eebb526ae5e9"
    Rule id: 6483
    Created at: 2020-03-18 10:14:25
    Updated at: 2020-03-19 12:09:08
    
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
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"

	strings:
		$a = "33d68e8b-7186-454f-8c2a-eebb526ae5e9"

	condition:
		
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		 
		$a
		
}
