/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: App Fortify Packer
    Rule id: 4139
    Created at: 2018-02-03 13:28:27
    Updated at: 2018-02-03 13:28:49
    
    Rating: #0
    Total detections: 117
*/

import "androguard"
import "file"
import "cuckoo"


rule app_fortify : packer
{
  meta:
    description = "App Fortify"

  strings:
    $lib = "libNSaferOnly.so"

  condition:
    $lib
}
