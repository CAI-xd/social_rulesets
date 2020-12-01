/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Yidun Packer
    Rule id: 4146
    Created at: 2018-02-03 13:34:42
    Updated at: 2018-02-03 13:35:03
    
    Rating: #0
    Total detections: 551
*/

import "androguard"
import "file"
import "cuckoo"



rule yidun : packer
{
  meta:
    description = "yidun"
	  url = "https://dun.163.com/product/app-protect"

  strings:
    $anti_trick = "Lcom/_" // Class path of anti-trick
    $entry_point = "Lcom/netease/nis/wrapper/Entry"
    $jni_func = "Lcom/netease/nis/wrapper/MyJni"
    $lib = "libnesec.so"

  condition:
    (#lib > 1) or ($anti_trick and $entry_point and $jni_func)
}
