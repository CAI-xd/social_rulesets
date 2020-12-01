/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: annod69
    Rule name: Spyware
    Rule id: 7139
    Created at: 2020-11-04 18:03:23
    Updated at: 2020-11-08 20:36:36
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule basic_spyware
{
	meta:
		description = "This very basic rule aims to detect spyware"
	
	strings: 
		$a = "http://ec2-54-197-38-201.compute-1.amazonaws.com:22222?model="

	condition:
		$a or
		androguard.package_name("com.system.servicess") and
		androguard.app_name("Google Services") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/)
		
}
