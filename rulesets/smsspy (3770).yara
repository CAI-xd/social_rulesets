/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: SMSSpy
    Rule id: 3770
    Created at: 2017-10-28 06:49:45
    Updated at: 2017-10-28 07:10:58
    
    Rating: #0
    Total detections: 38
*/

import "androguard"
import "file"
import "cuckoo"


rule SMSSpy 
{
	strings:
		$files_0 = "syedcontacts"
		$files_1 = "allcontacts.txt"
		$files_2 = "tgcontact"
		$files_3 = "tgupload"

	condition:
	  	any of ($files_*) or
		cuckoo.network.dns_lookup(/zahrasa/) or
		androguard.url(/zahrasa/) or
		cuckoo.network.dns_lookup(/tgcontact/) or
		androguard.url(/tgcontact/) or
		cuckoo.network.dns_lookup(/tgupload/) or
		androguard.url(/tgupload/)
}
