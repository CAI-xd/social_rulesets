/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Aproov Packer
    Rule id: 4145
    Created at: 2018-02-03 13:34:01
    Updated at: 2018-02-03 13:34:20
    
    Rating: #0
    Total detections: 59
*/

import "androguard"
import "file"
import "cuckoo"


rule approov : packer
{
  meta:
    description = "Aproov"
	  url = "https://www.approov.io/"

  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"

  condition:
    $lib and $sdk_config
}
