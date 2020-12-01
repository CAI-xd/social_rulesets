/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Custom Chinese ChornClickers Packer (weak)
    Rule id: 4632
    Created at: 2018-07-09 08:00:13
    Updated at: 2018-07-09 08:00:30
    
    Rating: #0
    Total detections: 3922
*/

import "androguard"
import "file"
import "cuckoo"

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
    $a = "libhdus.so"
    $b = "libwjus.so"

  condition:
    all of them
}
