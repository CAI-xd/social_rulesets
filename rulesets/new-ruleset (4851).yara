/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Esmaeil
    Rule name: New Ruleset
    Rule id: 4851
    Created at: 2018-08-29 12:20:56
    Updated at: 2018-10-20 08:24:53
    
    Rating: #0
    Total detections: 31
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the instagram apps suspicious to password stealing"
		sample = "7ec580e72b93eb9c5f858890e979f2fe10210d40adc522f93faa7c46cd0958b0"

	strings:
		$instagram = "https://www.instagram.com/accounts/login"
		$password = "'password'"
		$addJavaScript = "addJavascriptInterface"

	condition:

		$instagram and
		$password and
		$addJavaScript
		
}
