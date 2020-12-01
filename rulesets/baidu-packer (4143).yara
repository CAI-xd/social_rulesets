/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Baidu Packer
    Rule id: 4143
    Created at: 2018-02-03 13:31:00
    Updated at: 2018-02-03 13:32:00
    
    Rating: #0
    Total detections: 2154
*/

import "androguard"
import "file"
import "cuckoo"

rule baidu : packer
{
  meta:
    description = "Baidu"

  strings:
    $lib = "libbaiduprotect.so"
    $encrypted = "baiduprotect1.jar"

  condition:
    ($lib or $encrypted)
}
