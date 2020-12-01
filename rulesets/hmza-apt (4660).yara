/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: hmza APT
    Rule id: 4660
    Created at: 2018-07-16 12:29:01
    Updated at: 2019-08-28 13:05:16
    
    Rating: #1
    Total detections: 8
*/

import "androguard"

rule APT_hmza
{
	meta:
		description = "This rule will be able to tag all hmza APT samples"
		hash_1 = "2d0a56a347779ffdc3250deadda50008d6fae9b080c20892714348f8a44fca4b"
		hash_2 = "caf0f58ebe2fa540942edac641d34bbc8983ee924fd6a60f42642574bbcd3987"
		hash_3 = "b15b5a1a120302f32c40c7c7532581ee932859fdfb5f1b3018de679646b8c972"
		hash_4 = "c7f79fcf491ec404a5e8d62d745df2fa2c69d33395b47bc0a1b431862002d834"
		author = "Jacob Soo Lead Re"
		date = "25-December-2018"
	condition:
		(androguard.service(/NetService/i)
		and androguard.receiver(/hmzaSurvival/i) 
		and androguard.receiver(/SystemUpteen/i)) or 
		(androguard.service(/NtSrvice/i)
		and androguard.receiver(/hzaSrvval/i) 
		and androguard.receiver(/SystmUptn/i))
}
