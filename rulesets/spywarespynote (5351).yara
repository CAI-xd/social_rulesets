/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: SpywareSpyNote
    Rule id: 5351
    Created at: 2019-03-12 00:14:41
    Updated at: 2019-07-02 01:10:32
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SpywareSpyNote
{
	meta:
		description = "Android SpyNote spyware"
		md5 = "22649508c8056351c6ad3a760c39ba39"
		
		
	strings:
		$a_1 = "c0c1c3a2c0c1c" fullword
		$a_2 = "e1x1114x61114e" fullword
		$a_3 = "key_logger" fullword
		$a_4 = "Do I have root" fullword


	
	condition:
		all of ($a_*)
		and
		filesize < 2MB
 			    
				
}
