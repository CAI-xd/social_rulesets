/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: ApkPacker
    Rule id: 4365
    Created at: 2018-04-23 12:41:40
    Updated at: 2018-04-23 12:42:03
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule apkpacker : packer
{
    meta:
        description = "ApkPacker"

    strings:
        $a = "assets/ApkPacker/apkPackerConfiguration"
        $b = "assets/ApkPacker/classes.dex"
        //$c = "assets/config.txt"
        //$d = "assets/sht.txt"

    condition:
        all of them
}
