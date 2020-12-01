/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_NqShield
    Rule id: 3157
    Created at: 2017-07-15 14:48:21
    Updated at: 2017-07-29 11:11:35
    
    Rating: #0
    Total detections: 218
*/

rule NqShield
{
	meta:
		description = "NqShield"
		
    strings:
		$nqshield_1 = "NqShield"
		$nqshield_2 = "libnqshieldx86"
		$nqshield_3 = "LIB_NQ_SHIELD"

	condition:
        any of them 
}
