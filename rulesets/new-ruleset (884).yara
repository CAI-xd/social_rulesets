/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: New Ruleset
    Rule id: 884
    Created at: 2015-10-04 11:37:21
    Updated at: 2015-10-04 11:45:01
    
    Rating: #0
    Total detections: 11029
*/

import "androguard"



rule rusSMSfraud
{
	meta:
		description = "russian porn fraud. tricks the user into a cordova app"

	strings:
		$a = "file:///android_asset/html/end.html"
		$b = "file:///android_asset/html/index.html"
		$c = "sendSms2(): "
	condition:
		all of them
		
}
