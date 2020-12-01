/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: Cellspy
    Rule id: 1663
    Created at: 2016-07-21 11:30:05
    Updated at: 2016-07-21 11:31:31
    
    Rating: #0
    Total detections: 4235
*/

import "androguard"
import "file"
import "cuckoo"


rule cellspy : monitor
{
	meta:
		sample = "2b1b61cc6e0e291c53bce9db0e20b536d3c8371ce92cad5fc1dec4fa3f9d06c3"


	condition:
		androguard.url(/cellspy.mobi/) or
		cuckoo.network.dns_lookup(/cellspy\.mobi/)
		
}
