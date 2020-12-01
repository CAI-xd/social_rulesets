/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: SecNeo Packer
    Rule id: 4154
    Created at: 2018-02-03 13:43:20
    Updated at: 2018-02-03 13:43:42
    
    Rating: #0
    Total detections: 2241
*/

import "androguard"
import "file"
import "cuckoo"

rule secneo : packer
{
  meta:
    description = "SecNeo"
    url = "http://www.secneo.com"

  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"

  condition:
    any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}
