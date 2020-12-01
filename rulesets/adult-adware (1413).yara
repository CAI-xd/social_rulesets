/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Adult Adware
    Rule id: 1413
    Created at: 2016-05-20 13:35:55
    Updated at: 2016-05-20 13:39:57
    
    Rating: #0
    Total detections: 44
*/

import "androguard"

rule AdultAdware : official
{
	meta:
		description = "This rule detects the variant from https://blogs.mcafee.com/mcafee-labs/sex-sells-looking-at-android-adult-adware-apps/"
		sample = "BB2E56B9259D945592D7A6DDDBCEDCF82DDF3E5A52232377B5648AAACC3F12FB"

	strings:
		$a = {26 41 64 73 43 6F 75 6E 74 3D}
		$b = {26 48 6F 75 72 53 69 6E 63 65 49 6E 73 74 61 6C 6C 3D}
		$c = {26 4F 72 69 49 50 3D}
		$d = {43 4F 4E 56}
		$e = {4C 6F 61 64 6F 66 66 65 72}
		$f = {58 58 41 44 53 43 4F 55 4E 54}
		


	condition:

		$a and $b and $c and $d and $e and $f  

		
}
