/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Jiagu (ApktoolPlus) Packer
    Rule id: 4597
    Created at: 2018-06-28 22:34:22
    Updated at: 2018-06-28 22:35:08
    
    Rating: #0
    Total detections: 21
*/

import "androguard"
import "file"
import "cuckoo"

rule jiagu_apktoolplus : packer
{
    meta:
        description = "Jiagu (ApkToolPlus)"
        sample      = ""
        url         = ""


    strings:
        $a = "assets/jiagu_data.bin"
        $b = "assets/sign.bin"
        $c = "libapktoolplus_jiagu.so"

    condition:
        all of them
}
