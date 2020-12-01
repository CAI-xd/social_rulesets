/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Tencent Packer2
    Rule id: 1021
    Created at: 2015-11-16 15:29:55
    Updated at: 2015-11-16 15:30:05
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "Tencent Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "com.tencent.StubShell.ProxyShell"
		$strings_a = "com.tencent.StubShell.ShellHelper"

	condition:
		any of them
}
