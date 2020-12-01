/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuyjukim
    Rule name: test
    Rule id: 6988
    Created at: 2020-07-01 04:17:11
    Updated at: 2020-07-01 04:17:11
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule test : official
{
	condition:
		androguard.filter("android.intent.action.PHONE_STATE")
}
