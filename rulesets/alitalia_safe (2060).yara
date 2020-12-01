/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: Alitalia_safe
    Rule id: 2060
    Created at: 2017-01-03 11:50:35
    Updated at: 2017-01-03 12:26:26
    
    Rating: #1
    Total detections: 18
*/

import "androguard"
import "file"
import "cuckoo"


rule safe : Alitalia
{


	condition:
		
		androguard.certificate.sha1("e58eacbcb251314d8afcb5a267dd247c9311afd2") 
		
}
