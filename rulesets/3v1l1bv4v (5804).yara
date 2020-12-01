/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: davidT
    Rule name: 3v1l1bv4v
    Rule id: 5804
    Created at: 2019-08-01 02:54:14
    Updated at: 2019-08-02 17:33:13
    
    Rating: #0
    Total detections: 7320
*/

import "androguard"


rule potentialFakeGoogle
{
	meta:
		description = "Some apps seems to be signing themselves fraudulently as Google, why?"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
	androguard.certificate.subject(/O=Google Inc./) or androguard.certificate.issuer(/O=Google Inc./)
		
}
