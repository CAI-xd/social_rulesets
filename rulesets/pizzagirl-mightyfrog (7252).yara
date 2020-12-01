/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Komerso
    Rule name: pizzagirl, mightyfrog
    Rule id: 7252
    Created at: 2020-11-10 21:10:46
    Updated at: 2020-11-10 22:09:48
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule flipcat
{
	meta:
		description = "This ruleset detects apps that could be malicious as ru.flipcat.niceplace"
		
		

	condition:
		androguard.url("https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg") and
		androguard.url("http://vignette2.wikia.nocookie.net/logopedia/images/d/d2/Google_icon_2015.png") or
		androguard.activity("org.mightyfrog.android.simplenotepad.NoteEditor") or 
		androguard.activity("com.oneminorder.pizzagirl.sdk.activity.StartActivity") and
		androguard.permission(/android.permission.BLUETOOTH/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
		
		
		
}
