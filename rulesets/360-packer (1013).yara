/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: 360 Packer
    Rule id: 1013
    Created at: 2015-11-13 10:56:50
    Updated at: 2015-11-13 10:58:58
    
    Rating: #0
    Total detections: 44287
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "360 Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "libprotectClass"
		$strings_a = "libqupc"
		$strings_c = "com.qihoo.util.StubApplication"
		$strings_d = "com.qihoo.util.DefenceReport"

	condition:
		any of them
}
