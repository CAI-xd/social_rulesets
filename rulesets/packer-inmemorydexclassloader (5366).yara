/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Packer InMemoryDexClassLoader
    Rule id: 5366
    Created at: 2019-03-25 10:40:48
    Updated at: 2019-03-25 10:41:16
    
    Rating: #0
    Total detections: 6194
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "InMemoryDexClassLoader"

	strings:
		$a = "InMemoryDexClassLoader"

	condition:
		$a
		
}
