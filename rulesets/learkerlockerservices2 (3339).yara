/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: LearkerLockerServices2
    Rule id: 3339
    Created at: 2017-08-08 09:35:29
    Updated at: 2017-08-08 11:22:18
    
    Rating: #0
    Total detections: 4
*/

import "androguard"
import "file"
import "cuckoo"


rule LeakerLocker2
{
	condition:
		androguard.service(/x\.u\.s/)
		
}
