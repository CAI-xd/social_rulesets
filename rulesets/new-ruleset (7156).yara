/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 2633965
    Rule name: New Ruleset
    Rule id: 7156
    Created at: 2020-11-06 14:15:08
    Updated at: 2020-11-06 14:19:10
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule HDVP : official
{
	meta:
		description = "This rule detects the HD Video Player application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	//strings:
		//No strings were found

	condition:
		androguard.package_name("kind.love.island") and
		androguard.app_name("HD Video Player") and
		androguard.activity(/clean.proud.utility.MainActivity/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81") and
		androguard.url(/ms.applovin.com/)
		
}
