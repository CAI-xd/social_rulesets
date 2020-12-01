/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Custom Chinese ChornClickers Packer
    Rule id: 4620
    Created at: 2018-07-03 21:56:14
    Updated at: 2018-07-05 16:58:45
    
    Rating: #0
    Total detections: 4220
*/

import "androguard"
import "file"
import "cuckoo"

rule chornclickers : packer
{

  meta:
    description = "Custom Chinese 'ChornClickers'"
    url         = "https://github.com/rednaga/APKiD/issues/93"
    example     = "0c4a26d6b27986775c9c58813407a737657294579b6fd37618b0396d90d3efc3"

  strings:
    $a = "lib/armeabi/libhdus.so"
    $b = "lib/armeabi/libwjus.so"

  condition:
    all of them
}
