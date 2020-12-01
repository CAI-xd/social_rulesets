/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mi3security
    Rule name: Cordova Applications
    Rule id: 2449
    Created at: 2017-04-12 17:38:59
    Updated at: 2017-04-12 17:54:21
    
    Rating: #0
    Total detections: 228182
*/

import "androguard"

rule cordova
{
	meta:
		description = "This rule detects Cordova Apps"

	strings:
		$a = "org.apache.cordova"
		$b = "com.adobe.phonegap"

	condition:
		$a or $b
		
		
}
