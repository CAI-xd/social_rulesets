/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mrthreat
    Rule name: Lokibot
    Rule id: 3771
    Created at: 2017-10-29 22:17:39
    Updated at: 2017-10-29 22:27:43
    
    Rating: #0
    Total detections: 1
*/

rule lokibot_grotez
{
	meta:
		description = "This rule detects the Loki iterration application, used to show all Yara rules potential"

	strings:
		$a = "certificato37232.xyz"
		$b = "47.91.77.112"

	condition:
		any of them
		
}
