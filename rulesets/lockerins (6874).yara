/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: LockerIns
    Rule id: 6874
    Created at: 2020-04-29 00:57:06
    Updated at: 2020-04-29 17:24:48
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule LockerIns{

meta:
	description="Detects Locker samples that encrypt the device files"
	author="skeptre[@]gmail.com"
	filetype="apk/classes.dex"
	date="04/28/2020"

strings:
	$a1="l956y/bVK0RXi9hvy6OVaw9XhtAhzLzXZ05Bi89gz+OdZVVKiMt3lA=="
	$a2="decryptDir"
	$a3="You've successfully unblocked your device"

condition:
	all of ($a*)


}
