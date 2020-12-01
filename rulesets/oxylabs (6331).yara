/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Lux
    Rule name: OxyLabs
    Rule id: 6331
    Created at: 2020-01-30 10:16:39
    Updated at: 2020-01-30 12:53:25
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule OxyLabs
{
	meta:
		description = "This rule detects what Norman say"

	strings: 
	
	$src1="oxylabs.io"
	$src2 = "us-pr.oxylabs.io"

	condition:
	$src1 or $src2

		
}
