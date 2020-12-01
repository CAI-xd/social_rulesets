/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Fake_video_apps
    Rule id: 4906
    Created at: 2018-09-26 19:41:31
    Updated at: 2018-10-04 19:22:17
    
    Rating: #0
    Total detections: 2432
*/

import "androguard"

rule Fake_video_apps
{
	meta:
		description = "Detects few Video Player apps"
		
	strings:
		$a_1 = "am/xtrack/StereoReceiver"
		$a_2 = "am/xtrack/LolaActivity"
		
		$b_1 = "http://ccthi.enconfhz.com"
 		$b_2 = "http://first.luckshery.com"
		$b_3 = "http://cthi.nconfhz.com"
		$b_4 = "http://three.nameapp.xyz"
		$b_5 = "http://api.jetbudjet.in"
		$b_6 = "http://api.mobengine.xyz"
		$b_7 = "http://con.rsconf.site"
		$b_8 = "http://one.nameapp.xyz"
		$b_9 = "http://get.confhz.space"
		$b_10 = "http://mi1k.io"

		
	condition:
		all of ($a_*) and 
 		any of ($b_*)	
	    
				
}
