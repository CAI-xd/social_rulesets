/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: iblancasa
    Rule name: New Ruleset
    Rule id: 1276
    Created at: 2016-03-14 13:15:49
    Updated at: 2016-03-14 13:17:03
    
    Rating: #0
    Total detections: 10481
*/

rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samples"
	
	strings:
		$a = "SandroRat"
	
	condition:
		$a
}
