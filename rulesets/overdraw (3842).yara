/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: MertCanALICI
    Rule name: OVERDRAW
    Rule id: 3842
    Created at: 2017-11-24 08:51:34
    Updated at: 2017-11-24 08:52:55
    
    Rating: #0
    Total detections: 552954
*/

import "androguard"


rule koodous : official
{
	meta:
		description = "This rule detects the overdraw applications"

	condition:
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
		
}
