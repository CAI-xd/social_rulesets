/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nimaarek
    Rule name: New Ruleset
    Rule id: 5917
    Created at: 2019-09-29 19:11:50
    Updated at: 2019-09-29 19:20:53
    
    Rating: #0
    Total detections: 0
*/

import "elf"

private rule upx_elf32_arm_stub : packer
{
  meta:
    description = "Contains a UPX ARM stub"

  strings:
    $UPX_STUB = { 1E 20 A0 E3 14 10 8F E2 02 00 A0 E3 04 70 A0 E3 00 00 00 EF 7F 00 A0 E3 01 70 A0 E3 00 00 00 EF }

  condition:
    $UPX_STUB
}
