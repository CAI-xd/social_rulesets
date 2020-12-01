/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fsalido
    Rule name: Whatsdog Fake
    Rule id: 933
    Created at: 2015-10-14 10:03:21
    Updated at: 2015-11-05 10:10:00
    
    Rating: #0
    Total detections: 27
*/

import "androguard"


rule whatsdog : test
{
	meta:
		description = "Fake Whatsdog apps"

	condition:		
		androguard.app_name("WhatsDog") and 
		not androguard.certificate.sha1("006DA2B35407A5A017F04C4C675B05D3E77808C9")
		
}
