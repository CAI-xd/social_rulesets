/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: New Ruleset
    Rule id: 1945
    Created at: 2016-11-03 18:34:00
    Updated at: 2016-11-03 18:35:36
    
    Rating: #0
    Total detections: 31
*/

rule demo2 
{
	meta:
		description = "demo"
		

	strings:
		$a = "Protected by Shield4J"
	    $b = "Spain1"
		$c = "Madrid1"
		$d = "Shield4J"

	condition:
		all of them		
}
