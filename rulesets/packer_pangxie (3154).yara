/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_PangXie
    Rule id: 3154
    Created at: 2017-07-15 14:46:23
    Updated at: 2017-07-15 15:00:34
    
    Rating: #0
    Total detections: 116
*/

rule PangXie
{
	meta:
		description = "PangXie"
		
    strings:
		$pangxie_1 = "libnsecure.so"

	condition:
        any of them 
}
