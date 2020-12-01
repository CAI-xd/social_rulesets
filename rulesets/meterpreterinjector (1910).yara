/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: meterpreterInjector
    Rule id: 1910
    Created at: 2016-10-17 08:10:44
    Updated at: 2016-11-21 12:05:02
    
    Rating: #0
    Total detections: 59
*/

import "androguard"
import "file"

rule koodous : official
{
	meta:
		description = "Ruleset to detect kwetza tool to inject malicious code in Android applications."
		url = "https://github.com/sensepost/kwetza"

	strings:
		$a = "maakDieStageVanTcp"wide ascii
		$b = "payloadStart"wide ascii
		$c = "leesEnLoopDieDing"wide ascii
	condition:
		all of them
}
