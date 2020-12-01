/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: testShopaholicSpyware_jan2020
    Rule id: 6349
    Created at: 2020-02-04 23:42:47
    Updated at: 2020-02-04 23:44:36
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule testShopaholicSpyware_jan2020
{
	meta:
		description = "This rule detects the a spyawre from  the blog below"
		blog = "https://securelist.com/smartphone-shopaholic/95544/"
		sample = "0a421b0857cfe4d0066246cb87d8768c"

	strings:
			$a1 = "tfile|config.jar"
    		$a2 = "osfields"
    		$a3 = "tpath#fields.css"
    		$a4 = "loadClass"
    		$a5 = "startH1"

	condition:
		all of ($a*)
		
}
