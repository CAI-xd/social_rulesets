/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: APKProtect Packer
    Rule id: 4152
    Created at: 2018-02-03 13:41:37
    Updated at: 2018-02-03 13:41:52
    
    Rating: #0
    Total detections: 742
*/

import "androguard"
import "file"
import "cuckoo"


rule apkprotect : packer
{
  meta:
    description = "APKProtect"

  strings:
    $key = "apkprotect.com/key.dat"
    $dir = "apkprotect.com/"
    $lib = "libAPKProtect.so"

  condition:
    ($key or $dir or $lib)
}
