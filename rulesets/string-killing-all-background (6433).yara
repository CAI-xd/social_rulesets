/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: String = "KIlling all background"
    Rule id: 6433
    Created at: 2020-02-28 16:14:00
    Updated at: 2020-03-18 15:30:59
    
    Rating: #0
    Total detections: 12
*/

import "androguard"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the Koodous application, used to show all Yara rules potential"
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"

	strings:
		$a = "Killing all background processes..."
		
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
		
}
