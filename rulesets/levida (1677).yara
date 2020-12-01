/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: Levida
    Rule id: 1677
    Created at: 2016-07-25 13:31:12
    Updated at: 2016-07-25 13:32:27
    
    Rating: #0
    Total detections: 54
*/

import "androguard"
import "cuckoo"


rule Levida
{

	condition:
		androguard.url(/safe\-server\-click\.com/) or 
		cuckoo.network.dns_lookup(/safe\-server\-click\.com/)
		
}
