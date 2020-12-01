/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: d3fl4t3
    Rule name: Approov
    Rule id: 6866
    Created at: 2020-04-24 06:35:50
    Updated at: 2020-08-21 16:24:33
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule approov
{
	meta:
        description = "Approov library"
	
	strings:
		$c2_1 = "approov" nocase
		
	condition:
		1 of ($c2_*)
}
