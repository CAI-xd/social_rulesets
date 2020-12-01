/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Bram0105
    Rule name: APK2
    Rule id: 7310
    Created at: 2020-11-13 12:11:32
    Updated at: 2020-11-13 12:27:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SaveMe
{
	meta:
		description = "This rule is to detect the SaveMe application"

	condition:
		//Find if the app still exists
		androguard.app_name("SaveMe") and
		
		//Permissions that are probably used by the SaveMe app, according to the information that is stated on Kharon. The app executes various commands, according to these events I assumed the permissions below
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission.WRITE_CALL_LOG/) and //write permission also gives read permission
		androguard.permission(/android.permission.WRITE_CONTACTS/) and //write permission also gives read permission
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and

		//the app sends data to the url below
		androguard.url("http://xxxxmarketing.com")
}
