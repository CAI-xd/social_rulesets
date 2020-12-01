/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: grbmal18
    Rule name: New Ruleset
    Rule id: 4666
    Created at: 2018-07-18 12:35:16
    Updated at: 2018-07-19 18:12:27
    
    Rating: #0
    Total detections: 423
*/

import "androguard"
import "file"
import "cuckoo"

rule allatoristrong : obfuscator
{
  meta:
    description = "Allatori"


  strings:
    $s = "ALLATORI" nocase
	$n = "ALLATORIxDEMO"

  condition:
    $s and not $n
}
