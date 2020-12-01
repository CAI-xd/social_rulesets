/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: DroidRt
    Rule id: 1704
    Created at: 2016-07-29 07:37:22
    Updated at: 2016-07-29 07:42:12
    
    Rating: #0
    Total detections: 7
*/

import "androguard"
import "file"
import "cuckoo"


rule DroidRt 
{
	meta:
		sample = "f50dc3592737532bc12ef4954cb2d7aeb725f6c5eace363c8ab8535707b614b3"

	condition:
		cuckoo.network.dns_lookup(/download\.moborobo\.com/)
}
