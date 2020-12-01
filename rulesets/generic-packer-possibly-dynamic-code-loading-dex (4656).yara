/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Generic Packer (possibly dynamic code loading) DEX
    Rule id: 4656
    Created at: 2018-07-15 18:35:19
    Updated at: 2019-03-28 02:44:29
    
    Rating: #0
    Total detections: 53555
*/

import "androguard"
import "file"
import "cuckoo"



rule could_be_packer : packer
{
    meta:
        description = "Generic Packer"

    strings:
        $a = /assets\/.{1,128}\.dex/
        $b = /assets\/[A-Za-z0-9.]{2,50}\.dex/
		
		$zip_head = "PK"
        $manifest = "AndroidManifest.xml"

    condition:
        ($a or $b) and
		($zip_head at 0 and $manifest and #manifest >= 2)
}
