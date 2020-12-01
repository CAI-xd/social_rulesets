/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Noelle
    Rule name: Tiffentom rule
    Rule id: 7342
    Created at: 2020-11-16 20:01:04
    Updated at: 2020-11-16 20:14:07
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule tiffintomsus
{
	meta:
		description = "This rule detects suspicious tiffintom activity"
		sample = "6e2c3900d9775696bd401cdfb6924f66c3283cd10666cebc930a1d01f9bf9807"

	condition:
		androguard.activity(/\.tiffintom\./) or
    	androguard.activity("com.tiffintom.tiffintom.sdk.activity.PermissionsActivity") 
		
}
