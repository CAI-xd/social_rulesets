/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: BluePilled
    Rule name: apperhand
    Rule id: 7375
    Created at: 2020-11-17 19:21:14
    Updated at: 2020-11-17 20:07:09
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule apperhand : trojan
{
	meta:
		description = "This rule detects the apperhand SDK aggressive adware."
		
	condition:
		androguard.url(/www\.apperhand\.com/) 
		and   			
		(androguard.permission(/android.permission.INTERNET/) 
		or
		androguard.permission(/android.permission.READ_HISTORY_BOOKMARKS/) 
		or
		androguard.permission(/android.WRITE_HISTORY_BOOKMARKS/) 
		or 
		androguard.permission(/android.permission.AUTHENTICATE_ACCOUNTS/)
		or
		androguard.permission(/android.permission.SET_TIME_ZONE/))
		
}
