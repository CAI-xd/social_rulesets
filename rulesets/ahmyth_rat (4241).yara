/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: ahmyth_rat
    Rule id: 4241
    Created at: 2018-02-28 22:56:19
    Updated at: 2018-03-01 19:39:20
    
    Rating: #0
    Total detections: 240
*/

import "androguard"
import "file"
import "cuckoo"


rule ahmyth_rat
{
	meta:
		description = "This rule detects malicious spawns of Ahmyth RAT"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.service(/ahmyth.mine.king.ahmyth.MainService/) and
		androguard.receiver(/ahmyth.mine.king.ahmyth.MyReceiver/)
		
}
