/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: ChinesePorn
    Rule id: 1679
    Created at: 2016-07-26 03:33:29
    Updated at: 2016-07-26 07:10:46
    
    Rating: #0
    Total detections: 711
*/

import "cuckoo"


rule PaPaVideo
{   
	meta:
		sha256 = "e6e362a100906988a68b322e28874d8234a03c1147b5bab8fb80867db3ce08a5"

	condition:
		cuckoo.network.dns_lookup(/tyuio\.127878\.com/) or
		cuckoo.network.dns_lookup(/www\.ayroe\.pw/)
		
}

rule MeiHuoVideo
{
	meta:
		sha256 = "452b79e21757af4c38735845b70a143fdbdef21c9e5b7a829f7a670192fbda8f"
		
	condition:
		cuckoo.network.dns_lookup(/app\.97aita\.com/) or
		cuckoo.network.dns_lookup(/sx\.ifanhao\.cc/) or 
		cuckoo.network.dns_lookup(/qubo\.kandou\.cc/) or 
		cuckoo.network.dns_lookup(/imgtu\.chnhtp\.com/)
		
}
