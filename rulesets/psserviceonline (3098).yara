/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jimmy
    Rule name: Psserviceonline
    Rule id: 3098
    Created at: 2017-07-07 16:53:04
    Updated at: 2017-07-07 17:14:26
    
    Rating: #0
    Total detections: 256
*/

import "androguard"
import "cuckoo"


rule psserviceonline : urlbased
{
	meta:
		description = "This rule detects APKs that contat a well-known malware infection source 						https://blog.checkpoint.com/2015/09/21/braintest-a-new-level-of-sophistication-in-mobile-malware/"

		sample = "422fec2e201600bb2ea3140951563f8c6fbd4f8279a04a164aca5e8e753c40e8"

	strings:
		$malicious_url = "psserviceonline.com"
		$malicious_url_2 = "psservicedl.com"
		$malicious_url_3 = "himobilephone.com"
		$malicious_url_4 = "adsuperiorstore.com"
		$malicious_url_5 = "i4vip"

	condition:
		any of them 
		or androguard.url(/psserviceonline\.com/) or 
		cuckoo.network.dns_lookup(/psserviceonline\.com/) or 
		androguard.url(/psservicedl\.com/) or 
		cuckoo.network.dns_lookup(/psservicedl\.com/)
		
}
