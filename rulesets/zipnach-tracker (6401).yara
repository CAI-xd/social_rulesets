/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: ZIPNach Tracker
    Rule id: 6401
    Created at: 2020-02-17 09:00:26
    Updated at: 2020-02-17 09:00:51
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule zipnach_detect
{
	meta:
		description = "This rule detects ZIPNach powered apps"
	strings:
		$a = "http://uat1.zipnach.com"
	condition:
		$a and
		androguard.permission(/android.permission.INTERNET/)		
}
