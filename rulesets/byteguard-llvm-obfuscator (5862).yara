/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: ByteGuard LLVM obfuscator
    Rule id: 5862
    Created at: 2019-08-21 11:41:21
    Updated at: 2019-12-26 00:28:05
    
    Rating: #0
    Total detections: 254
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "ByteGuard"

	strings:
		$a = "Apple LLVM version 6.0.0 (ByteGuard 0.9.3-af515063)"
		$c =  "(ByteGuard 0"

	condition:
		any of them
		
}
