/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: PangXie Packer
    Rule id: 4144
    Created at: 2018-02-03 13:33:25
    Updated at: 2018-02-03 13:33:37
    
    Rating: #0
    Total detections: 107
*/

import "androguard"
import "file"
import "cuckoo"


rule pangxie : packer
{
  meta:
    description = "PangXie"
    example = "ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c"

  strings:
    $lib = "libnsecure.so"

  condition:
    $lib
}
