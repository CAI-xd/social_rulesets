/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Packer_LIAPP
    Rule id: 3156
    Created at: 2017-07-15 14:46:46
    Updated at: 2017-07-15 14:59:24
    
    Rating: #0
    Total detections: 143
*/

rule LIAPP
{
	meta:
		description = "LIAPP"
		
    strings:
		$liapp_1 = "LiappClassLoader"
		$liapp_2 = "LIAPPEgg"
		$liapp_3 = "LIAPPClient"
		$liapp_4 = "LIAPPEgg.dex"

	condition:
        any of them 
}
