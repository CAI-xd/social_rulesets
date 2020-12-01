/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TauPan
    Rule name: ILightsService
    Rule id: 6283
    Created at: 2020-01-07 20:48:01
    Updated at: 2020-01-07 20:51:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule ILightsService : official
{
	meta:
		description = "This rule detects the android.app.ILightsService, see https://wuffs.org/blog/digitime-tech-fota-backdoors"

	condition:
	    androguard.service("android.app.ILightsService")		
}
