/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fsociety
    Rule name: Covid19 accessibility services
    Rule id: 6814
    Created at: 2020-04-01 08:11:08
    Updated at: 2020-04-01 08:24:25
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the Covid apps which use the accessibility services"

	condition:
		(androguard.package_name(/corona/i) or
		androguard.package_name(/covid/i) or
		androguard.app_name(/corona/i) or
		androguard.app_name(/covid/i)) and
		androguard.filter("android.accessibilityservice.AccessibilityService")
		
}
