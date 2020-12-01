/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: test123
    Rule name: New Ruleset
    Rule id: 1275
    Created at: 2016-03-14 13:15:46
    Updated at: 2016-03-14 13:18:54
    
    Rating: #0
    Total detections: 10502
*/

rule sandrorat
{
	meta:
		description = ""
		
	strings:
		$a = "sandrorat" nocase

	condition:
		$a
		
}
