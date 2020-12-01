/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Bangcle Packer
    Rule id: 4137
    Created at: 2018-02-03 13:26:52
    Updated at: 2018-02-03 13:27:17
    
    Rating: #0
    Total detections: 2150
*/

import "androguard"
import "file"
import "cuckoo"


rule bangcle : packer
{
  meta:
    description = "Bangcle"

  strings:
    $main_lib = "libsecexe.so"
    $second_lib = "libsecmain.so"
    $container = "assets/bangcleplugin/container.dex"
    $encrypted_jar = "bangcleclasses.jar"
    $encrypted_jar2 = "bangcle_classes.jar"

  condition:
    any of ($main_lib, $second_lib, $container, $encrypted_jar, $encrypted_jar2)
}
