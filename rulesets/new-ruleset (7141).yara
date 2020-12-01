/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 2633965
    Rule name: New Ruleset
    Rule id: 7141
    Created at: 2020-11-05 09:12:54
    Updated at: 2020-11-06 14:14:34
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule HD Video Player : official
{
	meta:
		description = "This rule detects the HD Video Player application, used to show all Yara rules potential"
		sample = "7b289810d1a0d3f62a60c4711f28f9d72349d78f0a0e3ea3aa6234e10cf0e344"

	//strings:
		//No strings were found
		
	condition:
		androguard.package_name("kind.love.island") and
		androguard.app_name("HD Video Player") and
		androguard.activity(/clean.proud.utility.MainActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81") and
		androguard.url(/ms.applovin.com/)
		
}
