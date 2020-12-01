/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: colorful233
    Rule name: bankbot_related
    Rule id: 6954
    Created at: 2020-06-03 05:33:58
    Updated at: 2020-06-03 05:55:30
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "bank malware related"
		sample = "none"

	strings:
		$a = "bankaccount"
		$b = "msky/*/phonecall/"

	condition:
		androguard.certificate.sha1("5312c4f491cbb55f890e8b4206c890fd48ab49c5") 
		or $a
		or $b
}
