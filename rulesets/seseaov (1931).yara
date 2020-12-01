/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: SeSeAOV
    Rule id: 1931
    Created at: 2016-10-25 07:53:46
    Updated at: 2017-11-15 03:06:26
    
    Rating: #0
    Total detections: 9483
*/

import "androguard"
import "file"
import "cuckoo"


rule SeSeAOV : SexApp
{
	meta:
		sample = "f93222a685f45487732e1692d6c1cbeb3748997c28ca5d61c587b21259791599"

	condition:
		cuckoo.network.dns_lookup(/h.\.tt-hongkong.com/)
		
}
