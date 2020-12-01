/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: SpyNet
    Rule id: 1705
    Created at: 2016-07-29 09:38:29
    Updated at: 2016-07-29 10:07:21
    
    Rating: #0
    Total detections: 1041
*/

import "file"

rule SpyNet
{
	meta:
		description = "Ruleset to detect SpyNetV2 samples. "
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	$a = "odNotice.txt"
	$b = "camera This device has camera!"
	$c = "camera This device has Nooo camera!"
	$d = "send|1sBdBBbbBBF|K|"
	$e = "send|372|ScreamSMS|senssd"
	$f = "send|5ms5gs5annc"
	$g = "send|45CLCLCa01"
	$h = "send|999SAnd|TimeStart"
	$i = "!s!c!r!e!a!m!"
	condition:
		4 of them 
}
