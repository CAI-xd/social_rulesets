/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: BangclePacker
    Rule id: 1015
    Created at: 2015-11-13 11:15:47
    Updated at: 2015-11-13 11:17:02
    
    Rating: #0
    Total detections: 20387
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "Bangcle Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "assets/bangcleplugin"
		$strings_a = "neo.proxy.DistributeReceiver"

	condition:
		any of them
}
