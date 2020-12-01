/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: VerificationScam
    Rule id: 5350
    Created at: 2019-03-12 00:14:41
    Updated at: 2019-07-02 01:10:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule VerificationScam
{
	meta:
		description = "Android Verification scam"
		md5 = "4e37fe6a140b64a281e2ea08b2c116f0"
		
		
	strings:
		$a_2 = "verifycaptcha.com"
		$a_3 = "Mobile Verification required!"


	
	condition:
		all of ($a_*)
 			    
				
}
