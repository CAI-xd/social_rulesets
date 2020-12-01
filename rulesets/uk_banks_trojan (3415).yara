/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: UK_Banks_Trojan
    Rule id: 3415
    Created at: 2017-08-18 11:44:08
    Updated at: 2017-08-23 14:36:44
    
    Rating: #0
    Total detections: 7
*/

import "androguard"

rule MUK_Banks_Trojan
{
	meta:
		description = "This rule detects Mazain banker"
		sample = "579b632213220f9fd2007ff6054775b7c01433f4d7c43551db21301b2800cd8c"


	strings:
		$ = "5.45.87.115"
		$ = "twitter.com"


	condition:
		1 of them
		and androguard.package_name("com.acronic")	
}
