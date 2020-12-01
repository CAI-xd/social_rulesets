/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: New Ruleset
    Rule id: 883
    Created at: 2015-10-04 11:14:31
    Updated at: 2015-10-04 11:15:11
    
    Rating: #0
    Total detections: 42
*/

import "androguard"


rule sending2smtp
{
	meta:
		description = "Connects with remote chinese servers"
		
	strings:
		$a = "18201570457@163.com"
		$b = "smtp.163.com"

	condition:
		$a and $b
		
}
