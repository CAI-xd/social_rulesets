/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Alibaba Packer
    Rule id: 4142
    Created at: 2018-02-03 13:30:21
    Updated at: 2018-02-03 13:30:57
    
    Rating: #0
    Total detections: 157
*/

import "androguard"
import "file"
import "cuckoo"


rule alibaba : packer
{
  meta:
    description = "Alibaba"

  strings:
    $lib = "libmobisec.so"

  condition:
    $lib
}
