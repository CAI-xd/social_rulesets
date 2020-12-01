/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: Umeng.Adware
    Rule id: 604
    Created at: 2015-06-17 15:37:16
    Updated at: 2015-10-27 12:48:14
    
    Rating: #1
    Total detections: 898450
*/

import "cuckoo"


rule Umeng
{
	meta:
		description = "Evidences of Umeng advertisement library / Adware "

	condition:
		cuckoo.network.dns_lookup(/alog.umeng.com/) or cuckoo.network.dns_lookup(/oc.umeng.com/)
		
}
