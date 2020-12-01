/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: LuLuVideo
    Rule id: 1660
    Created at: 2016-07-21 10:35:42
    Updated at: 2016-07-21 11:12:53
    
    Rating: #0
    Total detections: 36
*/

import "cuckoo"


rule luluvideo : chinese_porn
{
	meta:
		sample = "f243a64965619acc4523e8e738846a3983ad91650bd41ce463a3a3ff104ddfd1"

	condition:
		cuckoo.network.http_request(/www\.sexavyy\.com:8088/) or 
		cuckoo.network.http_request(/spimg\.ananyy\.com/)
}
