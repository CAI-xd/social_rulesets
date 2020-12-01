/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Disane
    Rule name: Marcher2017_Activities_Receivers_Services
    Rule id: 3867
    Created at: 2017-12-04 15:30:13
    Updated at: 2017-12-04 15:35:05
    
    Rating: #0
    Total detections: 45
*/

import "androguard"


rule marcher_v2
{
	meta:
		description = "Detect marcher based on activity, service, receiver names."
		sample = "d7ff6de3f8af4af7c740943af3aaaf631a8baec42090f902bd7517e0190a1a21"

	condition:
		androguard.activity(/\.p0[0-9]{2}[a-z]\b/) and
		androguard.service(/\.p0[0-9]{2}[a-z]\b/) and
		androguard.receiver(/\.p0[0-9]{2}[a-z]\b/)
}
