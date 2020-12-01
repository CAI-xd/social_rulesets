/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lennard372
    Rule name: Yara rule app1 (Introduction to Cyber Security)
    Rule id: 7192
    Created at: 2020-11-09 14:14:07
    Updated at: 2020-11-09 14:58:50
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		name = "Lennard Hordijk, Teun de Mast"
		studentnumber = "2716143, 2656566"
		sample = "804a0963b2df68d86b468ea776ef784ab9223135659673a0991c30114ef522e2"

	strings:
		$a = "http://s.appjiagu.com:80/pkl16.html"

	condition:
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and 
		$a 
		
}
