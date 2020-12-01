/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ElTrampero
    Rule name: fakeav
    Rule id: 1405
    Created at: 2016-05-18 11:08:21
    Updated at: 2016-05-21 09:48:52
    
    Rating: #0
    Total detections: 4604
*/

import "androguard"
//android.permission.SEND_SMS


rule fakeav_cert 
{
	meta:
		description = "fakeav msg premium"
		sample = ""


	condition:
		androguard.certificate.sha1("1C414E5C054136863B5C460F99869B5B21D528FC")
		
}

rule fakeav_url
{
	meta:
		description = "fakeav msg premium"
		sample = ""


	condition:
		androguard.url(/topfiless\.com\/rates\.php/) 
		
}
