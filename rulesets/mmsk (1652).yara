/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: Mmsk
    Rule id: 1652
    Created at: 2016-07-21 03:48:58
    Updated at: 2016-07-25 12:56:23
    
    Rating: #0
    Total detections: 15
*/

import "cuckoo"
import "androguard"

rule Mmsk: Downloader
{
		
	meta:
		sha1 = "2c2d28649ba525f8b9ae8521f6c5cd0ba2f8bb88"
		
    condition:
		androguard.url(/911mmsk\.com/) or
		cuckoo.network.dns_lookup(/cdn\.angrydigital\.com/) or
		cuckoo.network.dns_lookup(/911mmsk\.com/) or
		cuckoo.network.http_request(/dws\.mobiappservice\.net:8080/) or
		cuckoo.network.http_request(/211.137.56.201\/videoplayer/) or
		cuckoo.network.http_request(/c\.91fuxin\.com/) or
		cuckoo.network.http_request(/cdn\.gahony\.com\/apk/) or
		cuckoo.network.http_request(/dl\.cline\.net\.cn/) or
		cuckoo.network.http_request(/jkl\.cjoysea\.com:8080/)
		
}
