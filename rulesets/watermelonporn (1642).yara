/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: WatermelonPorn
    Rule id: 1642
    Created at: 2016-07-19 09:44:11
    Updated at: 2016-07-27 02:55:35
    
    Rating: #3
    Total detections: 20526
*/

import "androguard"
import "cuckoo"

rule porn : chinese
{
    
	condition:
		androguard.url(/www\.4006000790\.com/) or
		androguard.url(/wap\.xykernel\.cn/) or
		androguard.url(/aaxzz\.b0\.upaiyun\.com/) or
		cuckoo.network.dns_lookup(/wap\.xykernel\.cn/) or
		cuckoo.network.dns_lookup(/androd2\.video\.daixie800\.com/) or
		cuckoo.network.dns_lookup(/www\.4006000790\.com/)
		 
}
