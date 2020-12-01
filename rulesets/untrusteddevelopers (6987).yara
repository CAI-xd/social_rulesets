/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jim
    Rule name: UntrustedDevelopers
    Rule id: 6987
    Created at: 2020-06-29 22:10:58
    Updated at: 2020-07-26 13:21:35
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule UntrustedDevelopers
{
	meta:
		description = "This rule detects applications by untrusted developers."

	condition:
		androguard.certificate.sha1("A623DE0D0517731162C0D50CE439AFFCAA4B3A8B") and
		androguard.certificate.sha1("166073937926629F3FFE054BE80850B7F4CEFFEB")
		
}
