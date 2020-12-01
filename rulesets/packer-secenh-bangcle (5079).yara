/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Packer Secenh (Bangcle)
    Rule id: 5079
    Created at: 2018-11-26 16:43:38
    Updated at: 2019-03-03 22:25:38
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule secenh : packer
{
  meta:
	description = "Secenh"
	sample = "0709d38575e15643f03793445479d869116dca319bce2296cb8af798453a8752"
	author = "Nacho Sanmillan"
  strings:
	$a1 = "assets/libseceh.so"
	$a2 = "assets/libseceh_x86.so"
	$b1 = "assets/respatcher.jar"
	$b2 = "assets/res.zip"
  condition:
	1 of ($a*) 
	and 1 of ($b*)
}
