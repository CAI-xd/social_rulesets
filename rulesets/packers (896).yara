/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Packers
    Rule id: 896
    Created at: 2015-10-08 08:09:47
    Updated at: 2015-10-08 08:11:27
    
    Rating: #1
    Total detections: 277315
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "packers"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "StubApplication"
		$strings_c = "libjiagu"


	condition:
		$strings_b or $strings_c
}
