/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Algo360 SDK Tracker
    Rule id: 6410
    Created at: 2020-02-20 08:50:10
    Updated at: 2020-02-20 08:51:02
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule algo360_detect
{
	meta:
		description = "This rule detects Algo360 Credit Score SDK apps"

	strings:
		$a = "iapi.algo360.com"
		$b = "https://uat.algo360.com:7777"		
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)		
}
