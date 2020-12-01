/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Generic Packer (possibly dynamic code loading) jar
    Rule id: 4659
    Created at: 2018-07-16 10:04:25
    Updated at: 2018-07-24 17:41:17
    
    Rating: #0
    Total detections: 4073
*/

import "androguard"
import "file"
import "cuckoo"



rule could_be_packer : packer
{
    meta:
        description = "Generic Packer"

    strings:
        $a = /assets\/.{1,128}\.jar/
        $b = /assets\/[A-Za-z0-9.]{2,50}\.jar/
		
		$zip_head = "PK"
        $manifest = "AndroidManifest.xml"

    condition:
        ($a or $b) and
		($zip_head at 0 and $manifest and #manifest >= 2)
}
