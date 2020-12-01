/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nimaarek
    Rule name: New Ruleset
    Rule id: 5916
    Created at: 2019-09-29 18:45:16
    Updated at: 2019-09-29 18:45:56
    
    Rating: #0
    Total detections: 2
*/

import "file"
import "elf"


rule promon : packer
{
  meta:
    description = "Promon Shield"
    url         = "https://promon.co/"
    sample      = "6a3352f54d9f5199e4bf39687224e58df642d1d91f1d32b069acd4394a0c4fe0"

  strings:
    $a = "libshield.so"
    $b = "deflate"
    $c = "inflateInit2"
    $d = "crc32"

    $s1 = /.ncc/  // Code segment
    $s2 = /.ncd/  // Data segment
    $s3 = /.ncu/  // Another segment

  condition:
    ($a and $b and $c and $d) and
    2 of ($s*)
}
