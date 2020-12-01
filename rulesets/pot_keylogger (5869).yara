/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: deedoz
    Rule name: Pot_Keylogger
    Rule id: 5869
    Created at: 2019-08-23 08:59:18
    Updated at: 2019-08-23 09:00:34
    
    Rating: #0
    Total detections: 378
*/

import "androguard"

rule Keylogger
{
    meta:
	description = "A potential Keylogger. looking for filter cuz andoguard cannot detect the inline permission"

    condition:
	androguard.filter(/accessibilityservice.AccessibilityService/) or
	androguard.permission(/BIND_ACCESSIBILITY_SERVICE/)

}
