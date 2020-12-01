/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: ita.RAT
    Rule id: 1730
    Created at: 2016-08-05 11:33:51
    Updated at: 2016-08-05 11:41:51
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "file"


rule citrusRAT {
	meta:
		description = "Ruleset to detect an Italian RAT." 
		sample = "f26658419a9113b0b79ecd58966aee93deec77ea713ff37af36c249002419310" 
	
	strings:
		$a = "/system/bin/screenrecord /sdcard/example.mp4"
		$b = "/system/bin/rm /sdcard/img.png"
		$c = "2.117.118.97"
		$d = "monitorSMSAttivo"
		$f = "+393482877835"
		$g = "fin qui OK 7"
		$h = "/system/xbin/"
	condition:
		all of them 

}
