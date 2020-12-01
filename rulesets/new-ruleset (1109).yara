/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Research
    Rule name: New Ruleset
    Rule id: 1109
    Created at: 2016-01-07 12:33:14
    Updated at: 2016-02-23 15:59:20
    
    Rating: #0
    Total detections: 2659757
*/

import "androguard"
import "file"
import "cuckoo"


rule test
{
    condition:
        androguard.target_sdk >= 23 or
		androguard.max_sdk >= 23 or
		androguard.min_sdk >= 23
}
