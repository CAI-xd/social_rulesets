/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Parse
    Rule id: 1610
    Created at: 2016-07-12 16:22:49
    Updated at: 2016-07-12 16:28:35
    
    Rating: #0
    Total detections: 41796
*/

import "androguard"
import "cuckoo"

rule parse
{
	meta:
		description = "This rule detects aplicactions relationship with http://parse.com/"
		sample = ""

	condition:
		cuckoo.network.dns_lookup(/api\.parse\.com/)
		
}
