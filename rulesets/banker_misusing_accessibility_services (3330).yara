/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: boni11
    Rule name: Banker_misusing_accessibility_services
    Rule id: 3330
    Created at: 2017-08-07 07:38:20
    Updated at: 2017-08-21 07:01:28
    
    Rating: #2
    Total detections: 48
*/

import "androguard"
import "file"


rule BankingTrojan
{
	meta:
		description = "This rule detects Banking Trojan missusing Accessibility services"
		sample = "4da711976f175d67c5a212567a070348eead1b6fbb1af184c50fdbbefa743f0f"

	strings:
		$required_1 = "getEnabledAccessibilityServiceList"
		$required_4 = "performAction"
		$required_5 = "getContentDescription"
		$required_6 = "getDefaultSmsPackage"
		$required_7 = "removeViewImmediate"
		$required_8 = "getDisplayOriginatingAddress"
		$required_9 = "isAdminActive"		

	condition:
		all of ($required_*) and 
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.EXPAND_STATUS_BAR/) and
		androguard.permission(/android.permission.READ_SMS/)
		
}
