/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: vern_dogservice
    Rule id: 3858
    Created at: 2017-12-01 13:58:18
    Updated at: 2017-12-07 11:49:45
    
    Rating: #0
    Total detections: 4
*/

import "androguard"
import "file"
import "cuckoo"


rule vern_dogservice
{
	condition:
		cuckoo.network.dns_lookup(/xsech.xyz/) or	
		cuckoo.network.dns_lookup(/cfglab.com/) or	
		cuckoo.network.dns_lookup(/strckl.xyz/) or	
		cuckoo.network.dns_lookup(/kyhub.com/) or 	
		cuckoo.network.dns_lookup(/adtsk.mobi/) or	
		cuckoo.network.dns_lookup(/ofguide.com/) or 
		cuckoo.network.dns_lookup(/dinfood.com/) or
		cuckoo.network.dns_lookup(/apphale.com/) or
		cuckoo.network.dns_lookup(/offseronline.com/)
}
