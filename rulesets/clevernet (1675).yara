/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: Clevernet
    Rule id: 1675
    Created at: 2016-07-25 09:24:14
    Updated at: 2016-07-25 09:25:37
    
    Rating: #0
    Total detections: 611
*/

import "androguard"


rule Clevernet : Adware
{
	condition:
		androguard.url(/clevernet/)
		
}
