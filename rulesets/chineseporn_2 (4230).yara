/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: ChinesePorn_2
    Rule id: 4230
    Created at: 2018-02-23 23:33:08
    Updated at: 2018-03-20 22:38:09
    
    Rating: #0
    Total detections: 25
*/

import "androguard"
import "file"
import "cuckoo"


rule ChinesePorn_2
{
	meta:
		description = "This rule detects dirtygirl samples"
		sample = "aeed925b03d24b85700336d4882aeacc"
		
	condition:
		androguard.receiver(/com.sdky.lyr.zniu.HuntReceive/) and
		androguard.service(/com.sdky.jzp.srvi.DrdSrvi/)

}
