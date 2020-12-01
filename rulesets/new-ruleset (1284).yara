/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: javiki
    Rule name: New Ruleset
    Rule id: 1284
    Created at: 2016-03-14 13:16:01
    Updated at: 2016-03-14 13:21:56
    
    Rating: #0
    Total detections: 11290
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
