/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Govindsharma
    Rule name: New Ruleset
    Rule id: 7422
    Created at: 2020-11-24 16:23:47
    Updated at: 2020-11-25 01:40:23
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
 import "file"
 import "cuckoo"
 
 
 rule koodous : official
 {
     meta:
         description = "Dexguard Detect in assets"
         sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
 
     strings:
     $a = /Created\-By\: DexGuard\, version.+
 
     condition:
         all of them
         
 }
