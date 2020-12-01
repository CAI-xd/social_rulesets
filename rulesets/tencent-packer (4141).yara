/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Tencent Packer
    Rule id: 4141
    Created at: 2018-02-03 13:29:44
    Updated at: 2018-02-03 13:30:13
    
    Rating: #0
    Total detections: 16990
*/

import "androguard"
import "file"
import "cuckoo"

rule tencent : packer
{
  meta:
    description = "Tencent"

  strings:
    $decryptor_lib = "lib/armeabi/libshell.so"
    $zip_lib = "lib/armeabi/libmobisecy.so"
    $classpath = "com/tencent/StubShell"
    $mix_dex = "/mix.dex"

  condition:
    ($classpath or $decryptor_lib or $zip_lib or $mix_dex)
}
