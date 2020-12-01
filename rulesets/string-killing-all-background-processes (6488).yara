/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: String = "Killing all background processes..."
    Rule id: 6488
    Created at: 2020-03-19 11:56:49
    Updated at: 2020-03-20 16:45:09
    
    Rating: #0
    Total detections: 7
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

		$a = "Killing all background processes..."
		
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
		
}
