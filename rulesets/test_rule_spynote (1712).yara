/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 5h1vang
    Rule name: test_rule_spynote
    Rule id: 1712
    Created at: 2016-08-01 14:57:51
    Updated at: 2016-09-29 07:35:12
    
    Rating: #0
    Total detections: 998
*/

import "androguard"



rule spynote_pkg
{
	meta:
		description = "Yara rule for detection of different Spynote based on pkg"
		source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "SERVER_IP" nocase
	condition:
		androguard.package_name("dell.scream.application") and 
		$str_1
}
