/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: DexGuard New
    Rule id: 5009
    Created at: 2018-10-21 18:39:09
    Updated at: 2018-12-04 10:25:35
    
    Rating: #0
    Total detections: 1679
*/

import "androguard"
import "file"
import "cuckoo"

rule dexguard_new : obfuscator
{
  meta:
    description = "DexGuard new"

  strings:
    // 1-byte size + size-bytes obfuscated class + 1-byte NULL terminator
    $Loaux   = { 07 4C 6F 2F (41|61) (55|75) (58|78) 3B 00 }  // Lo/[Aa][Uu][Xx];
    $Locon   = { 07 4C 6F 2F (43|63) (4F|6F) (4E|6E) 3B 00 }  // Lo/[Cc][Oo][Nn];
    $Lolcase = { 05 4C 6F 2F ?? 3B 00 }                       // Lo/[a-z];
    $Loucase = { 05 4C 6F 2F ?? 3B 00 }                       // Lo/[A-Z];
    $Loif    = { 06 4C 6F 2F ?? (46|66) 3B 00 }               // Lo/[iI][fF];
    $Loif1U  = { 08 4C 6F 2F ?? 24 (49|69) (46|66) 3B 00 }    // Lo/[A-Z]$[iI][fF];
    $Loif2UL = { 09 4C 6F 2F ?? ?? 24 (49|69) (46|66) 3B 00 } // Lo/[a-zA-Z][a-zA-Z]$[iI][fF];
    $Lo2c    = { 06 4C 6F 2F ?? ?? 3B 00 }                    // Lo/[a-zA-z][a-zA-z];
    $Lo2crap = { 05 4C 6F 2F ?? ?? 3B 00 }                    // Lo/crap;
    $Lo3crap = { 05 4C 6F 2F ?? ?? ?? 3B 00 }                 // Lo/crap;


    $lib_runtime = "libruntime.so"
    $dexguard    = "DexGuard" nocase
    $guardsquare = "guardsquare" nocase

  condition:
        ($lib_runtime or $dexguard or $guardsquare)
        or
        (($Loaux or $Locon))
        or
        ( ($Lolcase or $Loucase or $Lo2c or 1 of ($Loif*)) and ($Lo2crap or $Lo3crap) )
}
