/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Kony Packer
    Rule id: 4147
    Created at: 2018-02-03 13:35:16
    Updated at: 2018-02-03 13:35:38
    
    Rating: #0
    Total detections: 276
*/

import "androguard"
import "file"
import "cuckoo"


rule kony : packer
{
  meta:
    description = "Kony"
	  url = "http://www.kony.com/"

  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"

  condition:
    $lib and $decrypt_keys and $encrypted_js
}
