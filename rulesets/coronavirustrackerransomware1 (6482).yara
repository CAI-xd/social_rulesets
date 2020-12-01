/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: CoronaVirusTrackerRansomware1
    Rule id: 6482
    Created at: 2020-03-17 23:14:03
    Updated at: 2020-03-17 23:16:56
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule CoronaVirusTrackerRansomware1
{
	meta:
		description = "This rule detects CoronaVirus Tracker ransomware"
		sample = "d1d417235616e4a05096319bb4875f57"

	strings:
		$a1 = "qmjy6.bemobtracks"
		$a2 = "enter decryption code"
		$a3 = "You Phone is Decrypted"

	condition:
		all of ($a*)
}
