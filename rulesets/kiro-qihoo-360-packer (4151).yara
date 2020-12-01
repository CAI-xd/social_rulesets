/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Kiro-Qihoo 360 Packer
    Rule id: 4151
    Created at: 2018-02-03 13:40:16
    Updated at: 2018-02-03 13:41:16
    
    Rating: #0
    Total detections: 868
*/

import "androguard"
import "file"
import "cuckoo"


rule kiro : packer
{
  meta:
    description = "Kiro"

  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"

  condition:
    $kiro_lib and $sbox
}

rule qihoo360 : packer
{
  meta:
    description = "Qihoo 360"

  strings:
    $a = "libprotectClass.so"

  condition:
    $a and
    not kiro
}
