/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fsalido
    Rule name: SandroRat
    Rule id: 1285
    Created at: 2016-03-14 13:16:09
    Updated at: 2017-07-27 21:35:40
    
    Rating: #0
    Total detections: 9869
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
