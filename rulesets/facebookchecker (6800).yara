/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Dordy
    Rule name: FacebookChecker
    Rule id: 6800
    Created at: 2020-03-27 09:30:26
    Updated at: 2020-03-27 09:51:28
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "file"
import "cuckoo"


rule own : test
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential This is for test features of Koodous"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	

	condition:
	androguard.app_name("Facebook") and
		not androguard.package_name(/com.facebook.katana/) and 
		not androguard.certificate.issuer(/O=Facebook Mobile/)
		
}
