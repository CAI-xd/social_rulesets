/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Metaforic ELF
    Rule id: 5268
    Created at: 2019-02-11 17:45:28
    Updated at: 2019-02-11 17:46:46
    
    Rating: #0
    Total detections: 36
*/

import "androguard"
import "file"
import "cuckoo"


//https://github.com/rednaga/APKiD/blob/f1c3f3fe629ba6072735652c487096d3c10b3e6e/apkid/rules/elf/obfuscators.yara
rule metafortress : obfuscator
{
  meta:
    description = "MetaFortress"
    url         = "https://www.insidesecure.com/Products/Application-Protection/Software-Protection/Code-Protection"
    sample      = "326632f52eba45609f825ab6746037f2f2b47bfe66fd1aeebd835c8031f4fdb0"


  strings:
    $a = { 00 4d65 7461 466f 7274 7265 7373 3a20 2573 0025 733a 2025 730a 00 } // MetaFortress %s.%s: %s
    $b = { 00 4d65 7461 466f 7274 7265 7373 00 } // MetaFortress
    $c = "METAFORIC"

  condition:
    ($a and $b) or $c
}
