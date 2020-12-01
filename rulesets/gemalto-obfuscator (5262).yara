/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Gemalto Obfuscator
    Rule id: 5262
    Created at: 2019-02-08 22:38:21
    Updated at: 2019-02-08 22:40:17
    
    Rating: #0
    Total detections: 19
*/

import "androguard"
import "file"
import "cuckoo"

// https://github.com/rednaga/APKiD/commit/a605547cb84c1d7ae63132b11c117b121272173d
rule gemalto_protector : obfuscator
{
  meta:
    description = "Gemalto"


  strings:
    $l1 = "lib/arm64-v8a/libmedl.so"
    $l2 = "lib/armeabi-v7a/libmedl.so"
    $l3 = "lib/armeabi/libmedl.so"
    $l4 = "lib/mips/libmedl.so"
    $l5 = "lib/mips64/libmedl.so"
    $l6 = "lib/x86/libmedl.so"
    $l7 = "lib/x86_64/libmedl.so"

    $p1 = "Lcom/gemalto/idp/mobile/"
    $p2 = "Lcom/gemalto/medl/"
    $p3 = "Lcom/gemalto/ezio/mobile/sdk/"

  condition:
    2 of them
}
