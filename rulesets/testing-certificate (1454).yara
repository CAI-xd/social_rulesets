/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: testing certificate
    Rule id: 1454
    Created at: 2016-06-02 13:38:19
    Updated at: 2016-06-21 18:47:28
    
    Rating: #1
    Total detections: 108059
*/

import "androguard"

rule groups : authors2
{
	meta:
		description = "To find groups of apps with old testing certificate, signapk tool used it. Recently apps should not have this certificate"
		

	condition:
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81")

		
}
