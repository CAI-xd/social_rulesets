/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: ads.mopub.com
    Rule id: 1611
    Created at: 2016-07-12 16:30:59
    Updated at: 2016-07-13 10:26:16
    
    Rating: #0
    Total detections: 15563
*/

import "cuckoo"

rule mopub : adware
{
	meta:
		description = "This rule detects apks thats connects to http://www.mopub.com/ adware company - not reference for malware"
		sample = "273ea61d4aea7cd77e5c5910ce3627529428d84c802d30b8f9d6c8d227b324c1"

	condition:
		cuckoo.network.dns_lookup(/ads\.mopub\.com/)
		
}
