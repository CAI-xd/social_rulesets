/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Malicious_certificate
    Rule id: 3584
    Created at: 2017-09-13 07:19:36
    Updated at: 2017-09-14 15:22:27
    
    Rating: #0
    Total detections: 631
*/

import "androguard"


rule Malicious_certificate
{
	meta:
		description = "This rule detects Mazarbot samples for Raiffeisen bank"
		samples = "5c5f7f9e07b1e1c67a55ce56a78f717d"

	condition:
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB")
		
}
