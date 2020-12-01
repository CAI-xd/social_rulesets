/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nremynse
    Rule name: Viking
    Rule id: 4488
    Created at: 2018-05-31 13:45:37
    Updated at: 2018-05-31 16:40:16
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "cuckoo"

rule VikingMalware
{
	meta:
		description = "Viking like malware"
	strings:
		$a = "reportreward10.info:8830"
		
	condition:
		$a or
		androguard.url(/reportreward10\.info/) or
		cuckoo.network.dns_lookup(/185\.159\.81\.155/)
}
