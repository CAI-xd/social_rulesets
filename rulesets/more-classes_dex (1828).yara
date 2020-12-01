/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: More classes_dex
    Rule id: 1828
    Created at: 2016-09-20 12:48:39
    Updated at: 2016-09-20 12:50:05
    
    Rating: #0
    Total detections: 881032
*/

rule Moreclasses : findingfiles
{
	meta:
		description = "This rule detects if the app contains more than one classes file."

	strings:
		$a = "classes2.dex"
		$b = "classes3.dex"

	condition:
		any of them
}
