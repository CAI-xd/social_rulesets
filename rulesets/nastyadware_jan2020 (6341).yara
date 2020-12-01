/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: nastyAdware_jan2020
    Rule id: 6341
    Created at: 2020-02-04 00:45:31
    Updated at: 2020-02-05 00:00:12
    
    Rating: #0
    Total detections: 4
*/

import "androguard"
import "file"
import "cuckoo"


rule nastyAdware_jan2020
{
	meta:
		description = "This rule detects Adware malware discussed in https://labs.bitdefender.com/2020/01/seventeen-android-nasties-spotted-in-google-play-total-over-550k-downloads/" 
		
	strings:
        $a1 = "clcb.data"
        $a2 = "clcb"
        $b1 = "car.data"
        $b2 = "car3d"
        $c1 = "qrpr.data"
        $c2 = "codeqr"

	condition:
        all of ($a*) or all of ($b*) or all of ($c*)

		
}
