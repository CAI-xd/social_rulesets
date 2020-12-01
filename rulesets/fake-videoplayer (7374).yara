/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: s2630346
    Rule name: fake videoplayer
    Rule id: 7374
    Created at: 2020-11-17 18:54:57
    Updated at: 2020-11-17 20:25:46
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
rule video_player:fake
{ 	
	meta:
		description = "Determine if apk is a fake Video Player"
		sample = "b7d5732b1f0895724bac1fc20994341aed74e80d1f60f175196b98147ec5887c"


	condition:
		androguard.app_name("Video Player") and
		not androguard.certificate.sha1("7106c7423d7e70cd03db17c5b1cc9827")
}
