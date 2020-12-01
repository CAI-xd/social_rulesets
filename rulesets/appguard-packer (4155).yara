/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: AppGuard Packer
    Rule id: 4155
    Created at: 2018-02-03 13:43:54
    Updated at: 2018-02-03 13:44:13
    
    Rating: #0
    Total detections: 143
*/

import "androguard"
import "file"
import "cuckoo"


rule appguard : packer
{
  meta:
    description = "AppGuard"
    url = "http://appguard.nprotect.com/en/index.html"

  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"

  condition:
    ($stub and $encrypted_dex)
}
