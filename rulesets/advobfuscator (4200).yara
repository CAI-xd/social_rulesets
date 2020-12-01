/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: ADVobfuscator
    Rule id: 4200
    Created at: 2018-02-11 17:50:25
    Updated at: 2018-08-03 10:55:36
    
    Rating: #0
    Total detections: 3165
*/

import "androguard"
import "file"
import "cuckoo"


rule avdobfuscator : obfuscator
{
  meta:
    description = "AVDobfuscator"
    url         = "https://github.com/andrivet/ADVobfuscator"

  strings:
    $o1 = "ObfuscatedAddress"
    $o3 = "ObfuscatedCall"
    $o4 = "ObfuscatedCallP"
    $o5 = "ObfuscatedCallRet"
    $o6 = "ObfuscatedCallRetP"
    $o7 = "ObfuscatedFunc"

    //$elf_magic = { 7F 45 4C 46 }

  condition:
    1 of ($o*) //and $elf_magic at 0
}
