/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Task_Hijacking_2
    Rule id: 844
    Created at: 2015-09-21 17:38:26
    Updated at: 2015-09-21 17:39:45
    
    Rating: #0
    Total detections: 336356
*/

import "androguard"

rule taskhijack2 : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		
	strings:
		$a = "TaskStackBuilder"
	condition:
		
		$a 
		
}
