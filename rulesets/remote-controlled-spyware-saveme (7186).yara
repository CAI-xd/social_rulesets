/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Luisa369
    Rule name: Remote controlled spyware - SaveMe
    Rule id: 7186
    Created at: 2020-11-09 11:50:57
    Updated at: 2020-11-09 21:24:48
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule SaveMe : remote controlled spyware
{
	meta:
		description = "This rule detects the apk 'SaveMe' and similar apks"

	strings:
		$send_SMS_1 = "Send_ESms" nocase
		$send_SMS_2 = "SmsManager" nocase
		$send_SMS_3 = "sendTextMessage" nocase
		
		$display_webView = "WindowManager" nocase
		
		$make_call_1 = "android.intent.action.CALL" nocase
		$make_call_2 = "tel:" nocase
		$make_call_3 = "EXT_CALL" nocase
		
		$delete_call_1 = "content://call_log/calls" nocase
		$delete_call_2 = "number=?" nocase
		
		$end_call_1 = "com.android.internal.telephony.ITelephony" nocase
		$end_call_2 = "android.os.ServiceManager" nocase
		$end_call_3 = "android.os.ServiceManagerNative" nocase
		$end_call_4 = "getService" nocase
		$end_call_5 = "asInterface" nocase
		$end_call_6 = "fake" nocase
		$end_call_7 = "phone" nocase
		$end_call_8 = "endCall" nocase
		
		$steal_contacts_1 = "content://icc/adn" nocase		
		$steal_contacts_2 = "getColumnIndex" nocase
		$steal_contacts_3 = "name" nocase
		$steal_contacts_4 = "number" nocase		
		$steal_contacts_5 = "PHONE APP" nocase
		$steal_contacts_6 = "DatabaseOperations" nocase		
		$steal_contacts_7 = "sendcontact" nocase
		
		$pickContact_sendSMS = "deleteUser" nocase
		
		$remove_icon_1 = "setComponentEnabledSetting" nocase
		$remove_icon_2 = "COMPONENT_ENABLED_STATE_DISABLED" nocase
		$remove_icon_3 = "DONT_KILL_APP" nocase

	condition:
		androguard.app_name("SaveMe") or
        (
			any of ($send_SMS_*) and
			$display_webView and
			any of ($make_call_*) and
			any of ($delete_call_*) and
			any of ($end_call_*) and
			any of ($steal_contacts_*) and
			$pickContact_sendSMS and
			any of ($remove_icon_*)
		)
}
