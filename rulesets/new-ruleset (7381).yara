/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: heras1
    Rule name: New Ruleset
    Rule id: 7381
    Created at: 2020-11-17 21:03:10
    Updated at: 2020-11-17 22:57:44
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule findSample : similar
{
	condition:
		1
}
