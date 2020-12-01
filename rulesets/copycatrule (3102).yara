/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kpatsak
    Rule name: CopyCatRule
    Rule id: 3102
    Created at: 2017-07-09 21:24:45
    Updated at: 2017-07-09 21:31:20
    
    Rating: #0
    Total detections: 267
*/

import "androguard"
import "file"


rule CopyCatRule : official
{
	meta:
		description = "This rule detects the copycat malware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "mostatus.net"
		$b = "mobisummer.com"
		$c = "clickmsummer.com"
		$d = "hummercenter.com"
		$e = "tracksummer.com"

	condition:
		androguard.url("mostatus.net") or androguard.url("mobisummer.com") or
		androguard.url("clickmsummer.com") or androguard.url("hummercenter.com") or
		androguard.url("tracksummer.com")
		or $a or $b or $c or $d or $e
		
}
