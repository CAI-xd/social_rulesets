/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: miriki19
    Rule name: Disruptive Ads New
    Rule id: 6355
    Created at: 2020-02-05 22:07:54
    Updated at: 2020-02-06 16:01:57
    
    Rating: #0
    Total detections: 2246
*/

import "androguard"

global rule SuspPerm
{
   condition:
		androguard.permissions_number > 5 and
		androguard.permission(/(SEND|WRITE)_SMS/)

}

rule DisruptiveAds
{
	meta:
		description = "This rule detects apps that use distruptive ads"

	strings:
		$susp_string1 = "onBackPressed"
		$susp_string2 = "doubleBackToExitPressedOnce"

	condition:
		$susp_string1 or $susp_string2

}
