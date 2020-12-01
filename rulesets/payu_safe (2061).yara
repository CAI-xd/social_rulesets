/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: Payu_Safe
    Rule id: 2061
    Created at: 2017-01-03 11:51:46
    Updated at: 2017-01-03 11:51:58
    
    Rating: #1
    Total detections: 13
*/

import "androguard"

rule safe : PayU
{
	condition:
		
		androguard.certificate.sha1("bbb54a9135199f225e8a10e571d264a0e51601ef") 
		
}
