/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter
    Rule id: 3547
    Created at: 2017-09-05 00:02:22
    Updated at: 2017-09-13 03:16:17
    
    Rating: #0
    Total detections: 188
*/

import "androguard"
import "file"
import "cuckoo"


rule sorter : official
{
	condition:
		cuckoo.network.dns_lookup(/ds.dd.15/) or
		cuckoo.network.dns_lookup(/is.ca.15/) or
		cuckoo.network.dns_lookup(/q1.zxl/) or 
		cuckoo.network.dns_lookup(/sdk.vacuu/) or
		cuckoo.network.dns_lookup(/www.tb/) or
		cuckoo.network.dns_lookup(/www.vu/)
}
