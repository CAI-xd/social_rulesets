/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: DxShield Packer
    Rule id: 4156
    Created at: 2018-02-03 13:44:31
    Updated at: 2018-02-03 13:44:51
    
    Rating: #0
    Total detections: 6
*/

import "androguard"
import "file"
import "cuckoo"


rule dxshield : packer
{
  meta:
    description = "DxShield"
    url = "http://www.nshc.net/wp/portfolio-item/dxshield_eng/"

  strings:
    $decryptlib = "libdxbase.so"
    $res = "assets/DXINFO.XML"

  condition:
    ($decryptlib and $res)
}
