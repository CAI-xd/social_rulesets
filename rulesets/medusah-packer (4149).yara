/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Medusah Packer
    Rule id: 4149
    Created at: 2018-02-03 13:38:03
    Updated at: 2018-02-03 13:38:21
    
    Rating: #0
    Total detections: 163
*/

import "androguard"
import "file"
import "cuckoo"


rule medusah : packer
{
  meta:
    description = "Medusah"
    url = "https://medusah.com/"

  strings:
    $lib = "libmd.so"

  condition:
    $lib
}
