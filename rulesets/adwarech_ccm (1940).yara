/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: adwarech_ccm
    Rule id: 1940
    Created at: 2016-10-31 18:36:45
    Updated at: 2016-10-31 18:40:51
    
    Rating: #0
    Total detections: 31000
*/

rule adwareCh : ccm
{
	meta:
		description = "Test for chinease adware base on ccm"
		sample = "4ecfcf8ea0f4e3739fb95f7c41d05e065bfd6f6ba94ff3591abd2479b86eb8c7"

	strings:
		$S_18_12106 = { 12 14 71 10 ?? ?? 05 00 0c 01 71 10 ?? ?? 01 00 0c 02 71 10 ?? ?? 02 00 0a 00 38 00 26 00 6e 10 ?? ?? 01 00 0a 00 d8 00 00 fe 6e 10 ?? ?? 01 00 0a 03 d8 03 03 fe 71 53 ?? ?? 41 04 0c 00 6e 10 ?? ?? 01 00 6e 10 ?? ?? 00 00 0c 01 1a 03 ?? ?? 6e 20 ?? ?? 31 00 0c 01 6e 20 ?? ?? 41 00 6e 30 ?? ?? 01 02 11 00 07 10 28 fe }
		$S_18_6e32 = { 6e 10 ?? 00 02 00 0c 00 6e 20 ?? ?? 30 00 0c 00 71 10 ?? ?? 00 00 0c 01 6e 10 ?? ?? 00 00 11 01 }
		$S_18_d858 = { d8 00 03 00 e1 01 04 00 8d 11 4f 01 02 00 d8 00 03 01 e1 01 04 08 8d 11 4f 01 02 00 d8 00 03 02 e1 01 04 10 8d 11 4f 01 02 00 d8 00 03 03 e1 01 04 18 8d 11 4f 01 02 00 0e 00 }
		$S_18_1262 = { 12 11 1a 00 ?? ?? 6e 20 ?? 00 03 00 0c 00 1f 00 ?? 00 6e 10 ?? ?? 00 00 0c 00 38 00 10 00 6e 10 ?? ?? 00 00 0a 02 38 02 0a 00 6e 10 ?? ?? 00 00 0a 00 33 10 04 00 01 10 0f 00 12 00 28 fe }
		$S_18_d852 = { d8 00 05 00 48 00 04 00 d8 01 05 01 48 01 04 01 d8 02 05 02 48 02 04 02 d8 03 05 03 48 03 04 03 e0 01 01 08 b6 10 e0 01 02 10 b6 10 e0 01 03 18 b6 10 0f 00 }
		$S_18_1366 = { 13 00 0c 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 13 00 10 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 13 00 14 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 13 00 18 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 0e 00 }
	condition:
		all of them
		
}