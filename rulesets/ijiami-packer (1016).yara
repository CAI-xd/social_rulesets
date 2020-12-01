/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Ijiami Packer
    Rule id: 1016
    Created at: 2015-11-13 11:17:31
    Updated at: 2015-11-13 11:18:35
    
    Rating: #0
    Total detections: 49387
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "Ijiami Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "rmeabi/libexecmain.so"
		$strings_a = "neo.proxy.DistributeReceiver"

	condition:
		any of them
}
