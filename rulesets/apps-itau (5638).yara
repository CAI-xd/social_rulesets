/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ironbits
    Rule name: Apps Itau
    Rule id: 5638
    Created at: 2019-06-21 14:28:00
    Updated at: 2020-07-14 11:03:33
    
    Rating: #0
    Total detections: 1707
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : trojans_ttp
{
	meta:
        description = "trojans bankers com overlay e/ou acessibilidade"
		author = "Ialle Teixeira"
	
	strings:
		$c2_1 = "canairizinha" nocase
		$c2_2 = "conexao_BR" nocase
		$c2_3 = "progertormidia" nocase
		$c2_4 = "$controladores_BR" nocase
		$c2_5 = "Anywhere Software" nocase
		$c2_6 = "starter_BR" nocase
		$c2_7 = "b0z" nocase
		$c2_8 = "bolsonaro" nocase
		
	condition:
      androguard.package_name("com.itau") or any of them
}
