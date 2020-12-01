/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: MMVideo_Camera
    Rule id: 3485
    Created at: 2017-08-27 13:28:22
    Updated at: 2017-08-27 13:35:19
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule MMVideo_Camera : MMVideo
{
	meta:
		description = "This rule used to sort samples about 3457571382@qq.com"

	condition:
		cuckoo.network.dns_lookup(/35430\.com\.cn/) or
		cuckoo.network.dns_lookup(/338897\.com\.cn/) or
		cuckoo.network.dns_lookup(/33649\.com\.cn/)
		
}
