/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: shedun_adware_ccm
    Rule id: 1893
    Created at: 2016-10-07 14:54:17
    Updated at: 2016-10-11 11:35:29
    
    Rating: #-1
    Total detections: 20833
*/

rule shedum : signature
{
	meta:
		description = "This rule detects shedun adware by common code signature method"
		
	strings:
	$S_7138 = { 71 10 ?? 00 ?? 00 0c ?? 6e 30 ?? 00 ?? ?? 0c ?? 6e 30 ?? 00 ?? ?? 0c ?? 11 ?? 0d 00 6e 10 ?? 00 00 00 12 ?? 28 fa }
	$S_7146 = { 71 10 ?? 00 ?? 00 0c ?? 6e ?? ?? 00 ?? ?? 0c ?? 12 ?? 6e 20 ?? 00 ?? 00 6e ?? ?? 00 ?? ?? 0c ?? 11 ?? 0d 00 6e 10 ?? 00 00 00 12 ?? 28 fa }
	$S_7142 = { 71 10 ?? 00 ?? 00 0c ?? 6e 20 ?? 00 ?? 00 0c ?? 12 ?? 6e 20 ?? 00 ?? 00 6e 30 ?? 00 ?? ?? 0e 00 0d 00 6e 10 ?? 00 00 00 28 fb }
	$S_1240 = { 12 ?? 71 10 ?? 00 ?? 00 0c ?? 6e 30 ?? 00 ?? ?? 0c 01 12 ?? 6e 30 ?? 00 ?? ?? 0c ?? 11 ?? 0d ?? 6e 10 ?? 00 ?? 00 28 fb }
		

	condition:
		2 of them
		
}
