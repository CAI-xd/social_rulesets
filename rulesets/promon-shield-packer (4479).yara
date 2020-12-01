/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Promon Shield Packer
    Rule id: 4479
    Created at: 2018-05-29 20:17:52
    Updated at: 2018-05-29 20:18:12
    
    Rating: #1
    Total detections: 130
*/

import "androguard"
import "file"
import "cuckoo"


rule promon : packer
{
  meta:
    description = "Promon Shield"
    info        = "https://promon.co/"
    example     = "6a3352f54d9f5199e4bf39687224e58df642d1d91f1d32b069acd4394a0c4fe0"

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
