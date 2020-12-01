/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Task_Hijacking_allowTaskReparenting
    Rule id: 848
    Created at: 2015-09-21 18:42:47
    Updated at: 2015-09-21 18:43:41
    
    Rating: #0
    Total detections: 501
*/

import "androguard"

rule taskhijack4 : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		
	strings:
		$a = "allowTaskReparenting"
	condition:
		
		$a 
		
}
