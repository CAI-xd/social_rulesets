/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: reino
    Rule name: New DressCode
    Rule id: 5432
    Created at: 2019-04-09 16:14:16
    Updated at: 2019-05-27 21:04:35
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule newdress : official
{		 
		meta:
		description = "This rule detects Dresscode samples"
		
        strings:
                $a = /const-string v[0-9]?[0-9]?, "SVOOL"/
                $b = "wun03_mrxhn_mvg"
                $c = /const-string v[0-9]?[0-9]?, "XIVZGV"/
                $d = /const-string v[0-9]?[0-9]?, "KRMT"/
                $e = /const-string v[0-9]?[0-9]?, "HOVVK"/
                $f = /const-string v[0-9]?[0-9]?, "DZRG"/
                $g = /const-string v[0-9]?[0-9]?, "KLMT"/
        condition:
                $a or $b or $c or $d or $e or $f or $g
}
