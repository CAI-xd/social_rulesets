/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: Without String
    Rule id: 6485
    Created at: 2020-03-18 15:32:07
    Updated at: 2020-03-18 15:34:06
    
    Rating: #0
    Total detections: 312
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"


	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/)
		
}
