/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Arian
    Rule name: Detection of adware URLs
    Rule id: 7157
    Created at: 2020-11-07 13:07:56
    Updated at: 2020-11-09 01:44:09
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "cuckoo"

rule adware
{
	meta:
		description = "Used to identify apps using suspicious URLs (associated with adware)"

	condition:
		androguard.url("1downloadss0ftware.xyz") or cuckoo.network.dns_lookup(/1downloadss0ftware\.xyz/)
		or androguard.url("checkandgo.info") or cuckoo.network.dns_lookup(/checkandgo\.info/)
}
