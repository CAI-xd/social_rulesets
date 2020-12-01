/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: elenanofasto
    Rule name: New Ruleset
    Rule id: 1277
    Created at: 2016-03-14 13:15:50
    Updated at: 2016-03-14 13:18:30
    
    Rating: #0
    Total detections: 10547
*/

rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samles"
		
	strings:
		$a = "SandroRat" nocase
		
	condition:
		$a
}
