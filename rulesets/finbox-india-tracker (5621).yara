/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: FinBox India Tracker
    Rule id: 5621
    Created at: 2019-06-17 13:20:39
    Updated at: 2019-06-17 14:00:10
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule FinBoxINTracker
{
	meta:
		description = "This rule detects FinBox India SDK"
	strings:
		$a = "https://riskmanager.apis.finbox.in"
		$b = "https://api.finbox.in/api"
		$c = "https://logger.apis.finbox.in"		
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
