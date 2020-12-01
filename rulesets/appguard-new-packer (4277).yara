/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: AppGuard new Packer
    Rule id: 4277
    Created at: 2018-03-17 14:44:39
    Updated at: 2018-03-17 14:45:18
    
    Rating: #0
    Total detections: 183
*/

import "androguard"
import "file"
import "cuckoo"



rule appguard : packer
{
    meta:
        description = "AppGuard"
       
    strings:
        $c = "AppGuard0.jar"
        $d = "AppGuard.dgc"
        $e = "libAppGuard.so"
        $f = "libAppGuard-x86.so"

    condition:
        3 of them
}
