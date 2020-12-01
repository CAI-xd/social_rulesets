/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: guardit4j.fin
    Rule id: 5078
    Created at: 2018-11-24 13:35:27
    Updated at: 2018-11-26 23:18:26
    
    Rating: #0
    Total detections: 58
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "guardit4j.fin"


	strings:
		$a = "guardit4j.fin"

	condition:
		all of them
}
