/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: rootbeer
    Rule id: 3892
    Created at: 2017-12-10 00:33:31
    Updated at: 2017-12-10 00:34:10
    
    Rating: #0
    Total detections: 3629
*/

import "androguard"
import "file"
import "cuckoo"


rule rootbeer : anti_root
{

	strings:
		$rb = "Lcom/scottyab/rootbeer/RootBeerNative;"
		$cls = "RootBeerNative"
		$str = "tool-checker"

	condition:
		all of them
}
