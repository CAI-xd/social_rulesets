/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: jokeR
    Rule id: 6015
    Created at: 2019-10-30 10:15:45
    Updated at: 2019-12-19 06:57:53
    
    Rating: #0
    Total detections: 20
*/

import "androguard"
import "file"
import "cuckoo"


rule joker_camera : official
{

	condition:
		(androguard.app_name(/camera/) or
		androguard.app_name(/wallpaper/) or
		androguard.app_name(/game/)) and
		androguard.permission(/PHONE_STATE/) and
		androguard.permission(/CHANGE_WIFI_STATE/)
		
}
