/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grvarma
    Rule name: samsung_safe
    Rule id: 1883
    Created at: 2016-10-05 17:10:20
    Updated at: 2017-01-03 11:19:00
    
    Rating: #1
    Total detections: 0
*/

import "androguard"



private global rule samsung_Safe
{
	condition:
		androguard.certificate.sha1("9ca5170f381919dfe0446fcdab18b19a143b3163")
}
