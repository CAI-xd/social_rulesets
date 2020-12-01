/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jlgf
    Rule name: slembk_jl
    Rule id: 2828
    Created at: 2017-05-30 18:27:36
    Updated at: 2017-05-30 18:59:59
    
    Rating: #0
    Total detections: 20843
*/

import "androguard"
import "file"
import "cuckoo"

rule koodous : SlemBunk_Banker
{
	meta:
		description = "Slembunk_jl"

	strings:
		$a = "slem"
		$b = "185.62.188.32"
		$c = "android.app.extra.DEVICE_ADMIN"
		$d = "telephony/SmsManager"
	
	condition:
		$a and ($b or $c or $d)
		
}
