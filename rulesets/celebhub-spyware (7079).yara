/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Malware_Analysis
    Rule name: Celebhub Spyware
    Rule id: 7079
    Created at: 2020-10-06 11:47:11
    Updated at: 2020-10-06 12:01:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the celebhub Spyware"
		sample = "21e077ae3b20cfeb04026bc1bba540e73bf28dc62a578e45595f1c5421d29b87"

	strings:
		$a = ""

	condition:
		androguard.package_name("com.src.adulttime") and
		androguard.activity(/VideoActivity/i) and
		androguard.activity(/BaseActivity/i) and
		androguard.activity(/ContactActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.READ_SMS/)
}
