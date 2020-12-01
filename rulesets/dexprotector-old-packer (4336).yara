/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: DexProtector OLD Packer
    Rule id: 4336
    Created at: 2018-04-15 14:50:26
    Updated at: 2018-04-15 14:51:14
    
    Rating: #0
    Total detections: 51
*/

import "androguard"
import "file"
import "cuckoo"


rule dexprotector_old : packer
{

  meta:
    description = "DexProtector"

  strings:
    $encrptlib_1 = "assets/dp.arm-v7.art.kk.so"
    $encrptlib_2 = "assets/dp.arm-v7.art.l.so"
    $encrptlib_3 = "assets/dp.arm-v7.dvm.so"
    $encrptlib_4 = "assets/dp.arm.art.kk.so"
    $encrptlib_5 = "assets/dp.arm.art.l.so"
    $encrptlib_6 = "assets/dp.arm.dvm.so"
    $encrptlib_7 = "assets/dp.x86.art.kk.so"
    $encrptlib_8 = "assets/dp.x86.art.l.so"
    $encrptlib_9 = "assets/dp.x86.dvm.so"

    $encrptcustom = "assets/dp.mp3"

  condition:
    2 of ($encrptlib_*) and $encrptcustom
}
