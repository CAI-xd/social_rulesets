/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Dropper
    Rule id: 1176
    Created at: 2016-02-05 11:25:37
    Updated at: 2016-02-05 11:28:31
    
    Rating: #0
    Total detections: 1741
*/

import "androguard"
import "file"
import "cuckoo"


rule Dropper : official
{
	meta:
		description = "This rule detects a Dropper variant"
		sample = "05f486e38f642f17fbffc5803965a3febefdcffa1a5a6eeedd81a83c835656d4"

	condition:

		androguard.service("com.lx.a.ds") and
		androguard.receiver("com.lx.a.er")

		
}
