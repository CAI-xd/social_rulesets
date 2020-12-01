/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: StartAPP
    Rule id: 790
    Created at: 2015-08-20 08:30:30
    Updated at: 2015-10-22 05:36:08
    
    Rating: #0
    Total detections: 125855
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the fake installers."
		testing = "yes"
		sample = "6e57a0b0b734914da334471ea3cd32b51df52c2d17d5d717935373b18b6e0003" //Fake avast

	condition:
		androguard.activity(/com\.startapp\.android\.publish\.AppWallActivity/) and
		androguard.activity(/com\.startapp\.android\.publish\.list3d\.List3DActivity/)		
		
}
