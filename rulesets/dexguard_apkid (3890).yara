/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: dexguard_apkid
    Rule id: 3890
    Created at: 2017-12-10 00:26:13
    Updated at: 2017-12-10 00:27:07
    
    Rating: #2
    Total detections: 1096
*/

import "androguard"
import "file"
import "cuckoo"


rule dexguard : obfuscator
{
  meta:
    description = "DexGuard"

  strings:
    $opcodes = {
      00 06 00 01 00 03 00 00 00 00 00 00 00
      [20-65]
      0c 01
      12 12
      23 22 ?? ??
      1c 03 ?? ??
      12 04
      4d 03 02 04
      6e 3? ?? ?? 10 02
      0c 00
      62 01 ?? ??
      12 12
      23 22 ?? ??
      12 03
      4d 05 02 03
      6e 3? ?? ?? 10 02
      0c 00
      1f 00 ?? ??
      11 00
    }
    $a = "getClass"
    $b = "getDeclaredMethod"
    $c = "invoke"

  condition:
    $opcodes and
    all of ($a, $b, $c)

}
