/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_Naga
    Rule id: 3150
    Created at: 2017-07-15 14:44:14
    Updated at: 2017-07-15 15:01:16
    
    Rating: #0
    Total detections: 162
*/

rule Naga
{
	meta:
		description = "Naga"
		
    strings:
		$naga_1 = "libddog.so"

	condition:
        any of them 
}
