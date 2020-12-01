/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: qihoo packer
    Rule id: 1590
    Created at: 2016-07-07 15:39:05
    Updated at: 2016-07-08 15:04:42
    
    Rating: #0
    Total detections: 0
*/

rule packers : qihoo
{
	meta:
		description = "This rule detects packers based on files used by them"
		description2 = "This is for an old version, new versions use 360 and qihoo activities"
		

	strings:
		$qihoo_1 = "monster.dex"
    	$qihoo_2 = "libprotectClass"

	condition:
		2 of them
		
}
