/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: NQ Shield packer
    Rule id: 4140
    Created at: 2018-02-03 13:29:03
    Updated at: 2018-02-03 13:29:34
    
    Rating: #0
    Total detections: 284
*/

import "androguard"
import "file"
import "cuckoo"


rule nqshield : packer
{
  meta:
    description = "NQ Shield"

  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"

  condition:
    any of ($lib, $lib_sec1, $lib_sec2)
}
