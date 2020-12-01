/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ironbits
    Rule name: Obscuro Banking Trojan
    Rule id: 7256
    Created at: 2020-11-11 10:20:39
    Updated at: 2020-11-12 16:33:01
    
    Rating: #1
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : Obscuro Banking Trojan
{
	meta:
        description = "Trojan targeting Banks with Overlays"
		source = "https://securelist.com/ghimob-tetrade-threat-mobile-devices/99228/"
	
	strings:
		$c2_1 = "AppSealingService"
		$c2_2 = "AppSealingIPService"
		$c2_3 = "AccessibilityService"
		$c2_4 = "xmlpull"
		
	condition:
		2 of ($c2_*)
		and (
			androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/) 
			or androguard.permission(/android.permission.FOREGROUND_SERVICE/)) or
					
		//Certificate check based on my vt search
		androguard.certificate.sha1("E7BA28ECA0760524411B2D2476BDAE65C274B46A") or
		androguard.certificate.sha1("6DB41284B29ADF5FCFFFB3712D827161E26B504A") or
		androguard.certificate.sha1("E5029BA773B141CDD9C7352EA5BC63275B975303") or
		androguard.certificate.sha1("3BA519FBDDF5CB33203DC55255FA589FF4B0F983")
}
