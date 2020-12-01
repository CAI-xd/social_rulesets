/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Medusah (AppSolid) Packer
    Rule id: 4148
    Created at: 2018-02-03 13:36:43
    Updated at: 2018-02-03 13:37:52
    
    Rating: #0
    Total detections: 195
*/

import "androguard"
import "file"
import "cuckoo"




rule medusah : packer
{
  meta:
    description = "Medusah"
    url = "https://medusah.com/"

  strings:
    $lib = "libmd.so"

  condition:
    $lib
}


rule medusah_appsolid : packer
{
  meta:
    // Samples and discussion: https://github.com/rednaga/APKiD/issues/19
    description = "Medusah (AppSolid)"
    url = "https://appsolid.co/"

  strings:
    $encrypted_dex = "assets/high_resolution.png"

  condition:
    $encrypted_dex and not medusah
}
