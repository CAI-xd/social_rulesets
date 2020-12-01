/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: ThoughtCrime - WhisperSystems
    Rule id: 1006
    Created at: 2015-11-10 09:53:51
    Updated at: 2015-11-11 09:50:29
    
    Rating: #0
    Total detections: 427
*/

import "androguard"

rule thoughtcrime
{
	meta:
		description = "https://github.com/WhisperSystems/Signal-Android/tree/master/src/org/thoughtcrime/securesms"

	condition:
		androguard.permission(/org\.thoughtcrime\.securesms\.ACCESS_SECRETS/) or
		androguard.activity(/org\.thoughtcrime\.securesms\.*/) 
		
}
