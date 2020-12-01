/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chased
    Rule name: B test
    Rule id: 6927
    Created at: 2020-05-20 07:36:22
    Updated at: 2020-05-21 03:30:57
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule BITTER
{
	meta:
		description = "This rule detects BITTER"
		

	condition:
		androguard.package_name("com.secureImages.viewer.SlideShow") or
		androguard.package_name("Secure.ImageViewer") or
		androguard.package_name("droid.pixels") or
		androguard.package_name("eu.blitz.conversations") or
		androguard.package_name("com.picture.guard.view") or
		androguard.package_name("com.android.settings") 
		
		
}
