/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Tubi
    Rule name: Suspicious permissions
    Rule id: 6449
    Created at: 2020-03-07 12:29:08
    Updated at: 2020-03-08 18:03:40
    
    Rating: #0
    Total detections: 104
*/

import "androguard"
import "file"
import "cuckoo"


rule SuspiciousPermissions
{
	meta:
		description = "Yara rule to detect deceptive apps"

	strings:
		$susp_string1 = "onBackPressed"
		$susp_string2 = "doubleBackToExitPressedOnce"
		
	condition:
		$susp_string1 and $susp_string2		
}
