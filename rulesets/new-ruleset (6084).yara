/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: elichoen
    Rule name: New Ruleset
    Rule id: 6084
    Created at: 2019-11-03 18:53:31
    Updated at: 2019-11-03 18:56:47
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "dex"
include "common.yara"




private rule uses_telephony_class : internal
{
  meta:
    description = "References android.telephony.TelephonyManager class"

  strings:
    // Landroid/telephony/TelephonyManager;
    $a = {00 24 4C 61 6E 64 72 6F 69 64 2F 74 65 6C 65 70 68 6F 6E 79 2F 54
          65 6C 65 70 68 6F 6E 79 4D 61 6E 61 67 65 72 3B 00}
  condition:
    is_dex
    and $a
}



rule checks_device_id : anti_vm
{
  meta:
    description = "device ID check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // getDeviceId
    $a = {00 0B 67 65 74 44 65 76 69 63 65 49 64 00}
    // 000000000000000
    $b = {00 0F 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 00}

  condition:
    uses_telephony_class
    and all of them
}
