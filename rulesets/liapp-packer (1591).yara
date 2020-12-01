/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: LIAPP packer
    Rule id: 1591
    Created at: 2016-07-07 15:39:38
    Updated at: 2016-07-08 13:31:08
    
    Rating: #0
    Total detections: 112
*/

rule packers : liapp
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$liapp_1 = "LIAPPEgg.dex"
    	$liapp_2 = "LIAPPEgg"

	condition:
		2 of them
		
}
