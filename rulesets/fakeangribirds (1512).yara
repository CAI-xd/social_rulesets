/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: FakeAngribirds
    Rule id: 1512
    Created at: 2016-06-15 17:27:28
    Updated at: 2016-06-16 19:42:23
    
    Rating: #0
    Total detections: 1104
*/

import "androguard"


rule FakeAngribirds
{
	meta:
		description = "This ruleset looks for angribirds not by rovio"
		

	condition:
		androguard.activity(/com.rovio.fusion/i) and not
		androguard.certificate.sha1("66DA9177253113474F6B3043B89E0667902CF115") 
		
}
