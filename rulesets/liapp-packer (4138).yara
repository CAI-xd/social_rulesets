/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: LIAPP Packer
    Rule id: 4138
    Created at: 2018-02-03 13:27:55
    Updated at: 2018-02-03 13:28:12
    
    Rating: #0
    Total detections: 164
*/

import "androguard"
import "file"
import "cuckoo"


rule liapp : packer
{
  meta:
    description = "LIAPP"

  strings:
    $dir = "/LIAPPEgg"
    $lib = "LIAPPClient.sc"

  condition:
    any of ($dir, $lib)
}
