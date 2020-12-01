/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cafebabe
    Rule name: BITTER
    Rule id: 6157
    Created at: 2019-11-30 05:20:24
    Updated at: 2019-11-30 05:22:06
    
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
		sample = "7ad793b2c586b19753245fc901c3d087ef330804ab1836acba1e1eaaccfd5fb8 "

	condition:
		androguard.package_name("com.secureImages.viewer.SlideShow")
		
}
