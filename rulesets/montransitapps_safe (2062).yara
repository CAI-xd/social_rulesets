/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: MonTransitApps_safe
    Rule id: 2062
    Created at: 2017-01-03 11:57:20
    Updated at: 2017-01-03 11:59:14
    
    Rating: #1
    Total detections: 490
*/

import "androguard"
import "file"
import "cuckoo"


rule MonTransitApps : safe
{
	

	condition:
		androguard.certificate.sha1("ee6bb0756a02113fd46f2c434a06ebd5d04ff639")
		
}
