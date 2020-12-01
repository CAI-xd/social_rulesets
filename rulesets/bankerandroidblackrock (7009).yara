/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chaochaoxiong
    Rule name: Banker.Android.BlackRock
    Rule id: 7009
    Created at: 2020-07-24 02:41:53
    Updated at: 2020-07-31 15:27:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Banker.Android.BlackRock"
		sample = "32d2071ea8b7d815ab3455da2770b01901cef3fc26b9912f725a0a7de2f7d150"

	strings:
		 $a = "26kozQaKwRuNJ24t"
        $a1 = "Send_SMS"
        $a2 = "Flood_SMS"
        $a3 = "Download_SMS"
        $a4 = "Spam_on_contacts"
        $a5 = "Change_SMS_Manager"
        $a6 = "Run_App"
        $a7 = "StartKeyLogs"
        $a8 = "StopKeyLogs"
        $a9 = "StartPush"
        $a0 = "StopPush"
        $a10 = "Hide_Screen_Lock"
        $a11 = "Unlock_Hide_Screen"
        $a12 = "Admin"
        $a13 = "Profile"
        $a14 = "Start_clean_Push"
        $a15 = "Stop_clean_Push"

	condition:
		 all of them
		
}
