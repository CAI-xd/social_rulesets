/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: WhiteBroad
    Rule id: 5133
    Created at: 2018-12-11 14:17:49
    Updated at: 2018-12-11 15:13:21
    
    Rating: #0
    Total detections: 7
*/

import "androguard"

rule WhiteBroad
{
	meta:
		description = "This rule will be able to tag all the WhiteBroad stealer"
		hash_1 = "4e4a3c71818bbed5a8444c8f3427aabda8387e86576d1594bf30b9dbfe5ae25f"
		hash_2 = "75a7ccc2e9366e32aeeb34981eea0c90f6b0c536bf484d02ac8d3c4acac77974"
		hash_3 = "d8cac1a371a212189f1003340ffc04acecc1c6feeb3437efe06a52fef7ab74c6"
		hash_4 = "66c3d878f4613ab3929c98d9dd5d26c59501e50076c19c437b31ce899ff4a8cc"
		author = "Jacob Soo Lead Re"
		date = "10-December-2018"
	condition:
		androguard.service(/PkgHelper/i)
		and androguard.service(/SimpleWindow/i)
		and androguard.receiver(/KeepReceiver/i) 
		and androguard.receiver(/MessageReceiver/i) 
		and androguard.receiver(/ShowReceiver/i) 
		and androguard.activity(/MainActivity/i) 
}
