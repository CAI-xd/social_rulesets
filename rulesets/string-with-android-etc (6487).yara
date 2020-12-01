/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: String = "With android etc:"
    Rule id: 6487
    Created at: 2020-03-19 09:29:13
    Updated at: 2020-03-19 14:31:37
    
    Rating: #0
    Total detections: 156
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
		$a = "with android:layout_height=\x22wrap_content\x22"
		$b = "Points are coincident"

	
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and ($a or $b)
		
		
}
