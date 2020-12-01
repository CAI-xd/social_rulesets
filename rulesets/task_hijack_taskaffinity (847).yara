/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: TaSK_HIJACK_taskAffinity
    Rule id: 847
    Created at: 2015-09-21 18:42:00
    Updated at: 2015-09-21 18:42:30
    
    Rating: #0
    Total detections: 3680
*/

import "androguard"

rule taskhijack3 : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		
	strings:
		$a = "taskAffinity"
	condition:
		
		$a 
		
}
