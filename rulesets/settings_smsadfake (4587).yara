/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: settings_smsadfake
    Rule id: 4587
    Created at: 2018-06-25 13:15:48
    Updated at: 2018-06-25 13:37:34
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "droidbox"


rule sms_premium : official
{
	meta:
		description = ""
		sample = "3d7d3d27903a6269479be01dd777c50cb747b84b4d52c39a8e18401565acacdc"

	strings:
		$a = "assets/files/a-md/"

	condition:
		$a and
		droidbox.written.filename(/cache\/md.jar/) and 
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) 
		
		
}
