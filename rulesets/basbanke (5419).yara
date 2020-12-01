/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: BasBanke
    Rule id: 5419
    Created at: 2019-04-05 13:45:34
    Updated at: 2019-05-30 09:01:46
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "droidbox"

rule basbake
{
	meta:
		description = "This rule detects the basbanke app based on different indicators"
		family = "basbanke"

	strings:
		$s1 = "mwWwwi"
		$s2 = "MORhtW"
		$s3 = "assets/pismaim.balPK"
		$s4 = "assets/miguinha.balPK"
		$s5 = "TelephonyInfo.jarPK"
		$s6 = "MQ71"
		$s7 = "Filters.jar"
		$s8 = "TelephonyInfo.jar"
		$s9 = "descricao_brasil1"
		$s10 = "Quem visitou teu perfil Ative o recurso para funcionar"


	condition:
		(	any of ($s*) 
		  and
		  (
			  androguard.permission(/VIBRATE/) and
			  androguard.permission(/INTERNET/) and
			  androguard.permission(/BIND_WALLPAPER/) and
			  androguard.permission(/SYSTEM_OVERLAY_WINDOW/) and
			  androguard.permission(/ACCESS_NETWORK_STATE/) and
			  androguard.permission(/WAKE_LOCK/) and
			  androguard.permission(/SET_WALLPAPER/) and
			  androguard.permission(/WRITE_SETTINGS/) and
			  androguard.permission(/READ_PHONE_STATE/) and
			  androguard.permission(/SYSTEM_ALERT_WINDOW/) and
			  androguard.permission(/WRITE_EXTERNAL_STORAGE/)
		  )
		)
		or
		(
			droidbox.written.data(/VotosBolsonaro.txt/i) or
			droidbox.read.data(/VotosBolsonaro.txt/i) or
			
			droidbox.written.data(/xTravaLoop.txt/i) or
			droidbox.read.data(/xTravaLoop.txt/i) or
			
			droidbox.written.data(/xLepraFinal.txt/i) or
			droidbox.read.data(/xLepraFinal.txt/i) or
			
			droidbox.written.data(/Preta.txt/i) or
			droidbox.read.data(/Preta.txt/i) or
			
			droidbox.written.data(/xGolePrincipal.txt/i) or
			droidbox.read.data(/xGolePrincipal.txt/i) or
			
			droidbox.written.data(/pulissa.txt/i) or
			droidbox.read.data(/pulissa.txt/i) or
			
			droidbox.written.data(/pulissa.txt/i) or
			droidbox.read.data(/pulissa.txt/i)
			
		)
}
