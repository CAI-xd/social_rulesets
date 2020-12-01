/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: Jmede
    Rule id: 1684
    Created at: 2016-07-28 07:05:19
    Updated at: 2016-07-28 07:08:28
    
    Rating: #0
    Total detections: 121
*/

import "androguard"
import "file"
import "cuckoo"


rule jmede
{
	meta:
		description = "http://blog.avlsec.com/2016/07/3381/pokemon-go/"

	condition:
		cuckoo.network.dns_lookup(/if\.anycell\-report\.com/) or
		cuckoo.network.dns_lookup(/if\.jmede\.com/) or
		cuckoo.network.dns_lookup(/down\.tuohuangu\.com/)
		
}
