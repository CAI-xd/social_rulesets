/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Allatori Obfuscator (likely)
    Rule id: 4372
    Created at: 2018-04-25 11:40:12
    Updated at: 2018-05-01 10:09:23
    
    Rating: #0
    Total detections: 804
*/

import "androguard"
import "file"
import "cuckoo"

rule allatori : obfuscator
{
  meta:
    description = "Allatori (likely)"


  strings:
    $s = "ALLATORI" nocase
	$demo = "ALLATORIxDEMO"

  condition:
    $s and not $demo
}
