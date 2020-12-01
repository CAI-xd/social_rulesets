/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Russian Banker
    Rule id: 4331
    Created at: 2018-04-12 15:55:34
    Updated at: 2018-04-13 08:11:42
    
    Rating: #0
    Total detections: 63
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$service1="TTT.Sberbank"
		$service2="TTT.CardService"
		$service3="MainService"
		$service4="TTT.Avito"
		$service5="TTT.Alpha"
		$service6="TTT.Ali"
		$service7="TTT.vtb24"
		$service8="TTT.ural"

	condition:
	any	of them and  androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and androguard.filter(/ACTION_DEVICE_ADMIN_DISABLED/)
	
	}
