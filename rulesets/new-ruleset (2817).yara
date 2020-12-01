/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Maria
    Rule name: New Ruleset
    Rule id: 2817
    Created at: 2017-05-29 20:55:35
    Updated at: 2017-05-30 20:13:04
    
    Rating: #0
    Total detections: 82
*/

rule Slempo
{
	meta:
		description = "Slempo"
		
	strings:
		$a = "org/slempo/service/Main" nocase
		$b = "org/slempo/service/activities/Cards" nocase
		$c = "org/slempo/service/activities/CvcPopup" nocase
		$d = "org/slempo/service/activities/CommonHTML" nocase

	condition:
		$a and ($b or $c or $d)
		
}
