/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Bram0105
    Rule name: APK1
    Rule id: 7274
    Created at: 2020-11-12 15:35:03
    Updated at: 2020-11-13 12:07:37
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule virus1
{
	meta:
		description = "This rule is made to find the same virus in different apks"
		sample = "a7e231d20c56b7b797db8300176d64a2c65e319a3c6eea36c2acf9cf13cec200"

	strings:
		$s_message_to_1 = "3D Bowling would like to send a message to 7151"
		$s_message_to_2 = "3D Bowling would like to send a message to 9151"
		$s_message_to_3 = "3D Bowling would like to send a message to 2855"
		$s_message_to_4 = "3D Bowling would like to send a message to 88088"
		
		
	condition:
		// search for apps with the same name
		androguard.app_name("3D Bowling") or
	
		//check sha1 code to compare with other apks. Sha1 has it's own signature, meaning that other apps can match with it
		androguard.certificate.sha1("307ce61a54c38a7e1cf7cf111a0766e5891aca96") and
		
		//The service or services of an application are use to run tasks in background. Many times, the malware uses this to downloads configuration files, to send stolen data or another thing, ever in background.
		androguard.service("nht.r.LKJService") and
		
		//virusus will probably use the same receivers
		androguard.receiver("nht.r.LKJReceiver") and
		androguard.receiver("b.c.OphjReceiver") and
		
		//The activities is an esential part of the Android applications. They define the "screens" of an application and its logic, so, with the name of that, you can filter some applications.
		androguard.activity("b.c.JkActivity") and
		androguard.activity("nht.r.LKJWebA") and
		androguard.activity("nht.r.LKJHActivity") and
		
		//to see if the virus matches the same permissions
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.INSTALL_PACKAGES/) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		
		//these strings are a good indicator to check for comparison, as they use numbers that probably wont differ, as they are specially made for this situation
		$s_message_to_1 and
		$s_message_to_2 and
		$s_message_to_3 and
		$s_message_to_4
}
