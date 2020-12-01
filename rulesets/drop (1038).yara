/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Alon9191
    Rule name: Drop
    Rule id: 1038
    Created at: 2015-11-26 07:44:53
    Updated at: 2015-11-26 07:49:07
    
    Rating: #0
    Total detections: 658130
*/

rule drop
{
	meta:
		description = "This rule detects references to other applications"

	strings:
		$a = "Landroid/os/FileObserver"

	condition:
		$a
}
