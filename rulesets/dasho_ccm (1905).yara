/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: dasho_ccm
    Rule id: 1905
    Created at: 2016-10-12 17:38:12
    Updated at: 2016-10-13 15:40:17
    
    Rating: #0
    Total detections: 2
*/

rule dasho : ccm
{
	meta:
		description = "This rule detects dasho obfuscated apps"
		S_37_1270 = " { 12 00 6e 10 ?? ?? ?? 00 0c 02 21 23 32 30 10 00 49 01 02 00 dd 04 ?? 5f b7 14 d8 ?? ?? 01 d8 01 00 01 8e 44 50 04 02 00 01 10 28 f1 12 00 71 30 ?? ?? 02 03 0c 00 6e 10 ?? ?? 00 00 0c 00 11 00 0d 00 12 00 28 fd }		"

	strings:

		$S_127_7156 = { 71 00 ?? ?? 00 00 0b 00 18 02 80 ?? ?? ?? 56 01 00 00 31 00 00 02 3a 00 10 00 22 00 ?? ?? ?? ?? ?? ?? ?? ?? 71 20 ?? ?? 21 00 0c 01 70 20 ?? ?? 10 00 27 00 0d 00 0e 00 }
		$S_371_7158 = { 71 00 ?? ?? 00 00 0b 00 18 02 80 ?? ?? ?? 56 01 00 00 31 00 00 02 3a 00 11 00 22 00 ?? ?? ?? 01 ?? ?? ?? 02 ?? ?? 71 20 ?? ?? 21 00 0c 01 70 20 ?? ?? 10 00 27 00 0d 00 0e 00 }


	condition:
		all of them
		
}
