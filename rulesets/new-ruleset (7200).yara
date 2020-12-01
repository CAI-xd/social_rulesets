/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: louisekubatz
    Rule name: New Ruleset
    Rule id: 7200
    Created at: 2020-11-09 15:13:46
    Updated at: 2020-11-09 16:20:06
    
    Rating: #0
    Total detections: 0
*/

import "file"


rule cajino 
{
	meta:
		description = "This rule is made to identify Cajino or apps that are similar to Cajino"
		author = "LjmK"
		date = "09/11/2020"

	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE" nocase
		$b = "com.baidu.android.pushservice.action.RECEIVE" nocase
		$c = "com.baidu.android.pushservice.action.notification.CLICK" nocase
		$d = "BaiduUtils" nocase
		

	condition:
		
		$a and $b and $c or $d
		
}
