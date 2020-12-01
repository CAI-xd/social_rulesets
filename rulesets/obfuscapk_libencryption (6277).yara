/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: packmad
    Rule name: Obfuscapk_LibEncryption
    Rule id: 6277
    Created at: 2020-01-04 13:00:30
    Updated at: 2020-01-04 13:49:28
    
    Rating: #1
    Total detections: 0
*/

rule Obfuscapk_LibEncryption
{
  meta:
    description = "Obfuscapk - LibEncryption plugin"
    url         = "https://github.com/ClaudiuGeorgiu/Obfuscapk"
    author      = "packmad - https://twitter.com/packm4d"
    sample      = "4957d9c1b423ae045f27d97b1d0b1f32ba6a2ce56525a2e93bda7172ec18ad0c"
  strings:
    $lib_arm = /assets\/lib\.arm(eabi|64)-v[0-9a-zA-Z]{2}\.[!-~]+\.so/
    $lib_x86 = /assets\/lib\.x86(_64)?\.[!-~]+\.so/
  condition:
    any of them
}
