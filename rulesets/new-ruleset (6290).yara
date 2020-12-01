/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: sn81
    Rule name: New Ruleset
    Rule id: 6290
    Created at: 2020-01-09 18:49:19
    Updated at: 2020-01-09 18:50:52
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule TEST
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e5d8f5095be1d411a9946dd291ec7cca3e81963f574662110486c93d1b0b73b5"


	condition:
		androguard.package_name("com.bigpanda.puzzlegame.dragnmatch") 
		
}
