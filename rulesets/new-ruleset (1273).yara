/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kafka
    Rule name: New Ruleset
    Rule id: 1273
    Created at: 2016-03-14 13:15:43
    Updated at: 2016-03-14 13:18:51
    
    Rating: #0
    Total detections: 217193
*/

rule sandrorat
{
	meta:
		description = "Example"
	strings:
		$a = "Sandro"
	condition:
		$a
		
}
