/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Tencent Packer
    Rule id: 1014
    Created at: 2015-11-13 11:13:41
    Updated at: 2015-11-16 15:23:22
    
    Rating: #0
    Total detections: 7778
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
