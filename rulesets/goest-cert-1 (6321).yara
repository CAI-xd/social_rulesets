/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: h3xstream
    Rule name: Goest Cert 1
    Rule id: 6321
    Created at: 2020-01-27 22:28:56
    Updated at: 2020-11-18 19:54:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule geost : official
{
	meta:
		description = "This rule detects Trojan Banker"
		//sample = "203af6e58fb492bdd3f58b145959f15e0eb7e035bf22c2246b763c25dfc2c906"

	condition:
	    androguard.certificate.subject(/C:cn, CN:z, L:shanghai, O:z, ST:shanghai, OU:z/)
		
}
