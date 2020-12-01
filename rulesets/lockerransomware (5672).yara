/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: LockerRansomware
    Rule id: 5672
    Created at: 2019-07-02 01:05:19
    Updated at: 2019-07-03 18:43:51
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule LockerRansomware
{
	meta:
		description = "This rule detects apks relatedto the one mentioned on Twitter"
		tweet = "https://twitter.com/virqdroid/status/1144189572068327424"
		sample = "04f15f42b3d44142d8d1b44f95877ab4cdec9ba31d74a40cdea687bd833f142c"

	strings:
		$a1 = "L3N5c3RlbS9iaW4vc2g="
		$a2 = "Conta Gmail"
		$a3 = "Tutorial BTC"
		$a5 = "coockies"

	condition:
		all of ($a*)
		
}
