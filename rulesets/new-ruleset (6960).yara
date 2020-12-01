/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jejimenez
    Rule name: New Ruleset
    Rule id: 6960
    Created at: 2020-06-08 06:49:03
    Updated at: 2020-06-08 06:49:48
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule Jkdkdkd_Apps
{
	meta:
		description = "This rule detects the Jkdkdkd application"

	strings:
		$a = "Jkdkdkd"

	condition:
		$a
		
}
