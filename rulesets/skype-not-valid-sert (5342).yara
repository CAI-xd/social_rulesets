/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: Skype not valid sert
    Rule id: 5342
    Created at: 2019-03-06 15:27:49
    Updated at: 2019-03-06 15:34:11
    
    Rating: #0
    Total detections: 5
*/

import "androguard"
import "file"
import "cuckoo"


rule skype : notofficial
{
	meta:
		description = "Skype not valit key"

	condition:
		androguard.package_name("com.skype.raider") and
		not androguard.certificate.sha1("385567F1AEFB2647E8B42430C9AAF6259619C99C") and
		not androguard.certificate.sha1("93D59489E99C8FBE54F75C90EA87A76E86937C9C") 
		
		
}
