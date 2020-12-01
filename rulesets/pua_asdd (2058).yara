/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: PUA_ASDD
    Rule id: 2058
    Created at: 2017-01-03 11:35:05
    Updated at: 2017-01-03 11:36:30
    
    Rating: #1
    Total detections: 5606
*/

import "androguard"



rule PUA : ASDD
{
	

	condition:
		androguard.certificate.sha1("ed9a1ce1f18a1097dccc5c0cb005e3861da9c34a") 
		
}
