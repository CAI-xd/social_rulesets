/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: SysGhost
    Rule id: 1991
    Created at: 2016-11-28 09:50:31
    Updated at: 2017-11-15 03:05:48
    
    Rating: #0
    Total detections: 65
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "http://seclab.safe.baidu.com/2017-11/sysghost.html"

	condition:
		androguard.url(/iappease\.com\.cn/) or
		androguard.url(/ixintui\.com/) or
		androguard.url(/wit-wifi\.com/) or
		cuckoo.network.dns_lookup(/iappease\.com\.cn/) or
		cuckoo.network.dns_lookup(/ixintui\.com/) or
		cuckoo.network.dns_lookup(/wit-wifi\.com/)
		
}
