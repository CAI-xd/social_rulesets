/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Ijiami Packer
    Rule id: 4150
    Created at: 2018-02-03 13:39:28
    Updated at: 2018-02-03 13:39:46
    
    Rating: #0
    Total detections: 5408
*/

import "androguard"
import "file"
import "cuckoo"


rule ijiami : packer
{
  meta:
    description = "Ijiami"

  strings:
    $old_dat = "assets/ijiami.dat"
    $new_ajm = "ijiami.ajm"
    $ijm_lib = "assets/ijm_lib/"

  condition:
    ($old_dat or $new_ajm or $ijm_lib)
}
