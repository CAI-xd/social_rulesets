/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Allatori demo Obfuscator
    Rule id: 4371
    Created at: 2018-04-25 11:39:15
    Updated at: 2018-04-25 11:39:51
    
    Rating: #0
    Total detections: 448
*/

import "androguard"
import "file"
import "cuckoo"

rule allatori_demo : obfuscator
{
  meta:
    description = "Allatori demo"


  strings:
    $s = "ALLATORIxDEMO"

  condition:
    $s
}
