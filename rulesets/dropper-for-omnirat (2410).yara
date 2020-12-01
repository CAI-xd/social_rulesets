/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mwhunter
    Rule name: Dropper for OmniRAT
    Rule id: 2410
    Created at: 2017-04-04 09:51:27
    Updated at: 2017-04-04 10:36:20
    
    Rating: #1
    Total detections: 4
*/

import "androguard"
import "droidbox"


rule Dropper : OmniRAT Dropper
{
	meta:
        description = "Dropper for OmniRAT"
		

	condition:
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) 
		and androguard.activity(/net.filsh.youtubeconverter.MainActivity/)
}
