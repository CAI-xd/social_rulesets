/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: Feecode
    Rule id: 1678
    Created at: 2016-07-26 02:35:52
    Updated at: 2016-07-26 07:12:12
    
    Rating: #0
    Total detections: 1149
*/

import "androguard"
import "cuckoo"


rule Feecode : Payment
{
	condition:
		cuckoo.network.dns_lookup(/viapayplugdl\.feecode\.cn/) and
		
		not androguard.app_name("\xe8\xa5\xbf\xe7\x93\x9c\xe6\x88\x90\xe4\xba\xba\xe7\x89\x88") // xi gua cheng ren ban
		
}
