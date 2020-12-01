/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: Ginp
    Rule id: 6169
    Created at: 2019-12-02 14:38:24
    Updated at: 2019-12-16 10:56:56
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "droidbox"

rule Ginp
{
	meta:
		description = "This rule detects the Ginp app based on various info"
		family = "Ginp"

	strings:
		$s1 = /assets\/[a-zA-Z]{2,10}.jsonPK/
		$s2 = "Adobe Flash Player"
		$s3 = "Google Play Verificator"
		$s4 = "Battery Doctor Professional"
		$s5 = "Android 10 Updater"
		$s6 = "Flash Player"

	condition:
		$s1 and any of ($s*)

		and
		(	
			(
			  	androguard.permission("android.permission.ACCESS_FINE_LOCATION") and
			  	androguard.permission("android.permission.ACCESS_NETWORK_STATE") and
			  	androguard.permission("android.permission.CALL_PHONE") and
				androguard.permission("android.permission.FOREGROUND_SERVICE") and
				androguard.permission("android.permission.GET_TASKS") and
				androguard.permission("android.permission.INTERNET") and
				androguard.permission("android.permission.PACKAGE_USAGE_STATS") and
				androguard.permission("android.permission.READ_CONTACTS") and
				androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and
				androguard.permission("android.permission.READ_PHONE_STATE") and
				androguard.permission("android.permission.READ_SMS") and
				androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and
				androguard.permission("android.permission.RECEIVE_SMS") and
				androguard.permission("android.permission.RECORD_AUDIO") and
				androguard.permission("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS") and
				androguard.permission("android.permission.SEND_SMS") and
				androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and
				androguard.permission("android.permission.WAKE_LOCK") and
				androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and
				androguard.permission("android.permission.WRITE_SMS")
			)
			and
			(
				(
					androguard.receiver(/IncomingSmsListener/) or
					androguard.receiver(/ReceiverSMS/) or
					androguard.receiver(/ReceiverMms/) or
					androguard.receiver("ReceiverPushService") or
					androguard.receiver("ReceiverBoot")
				)
				or
			  	(
					androguard.service(/StartWhileGlobal/) or
					androguard.service(/StartWhileRequest/) or
					androguard.service(/ServiceShowToast/) or
					androguard.service(/ServiceAccessibility/) or
					androguard.service(/ServiceCommands/)
				)
			  	or
			  	(
					androguard.activity(/ActivityInjection/) or
					androguard.activity(/ActivityChangeSmsManager /) or
					androguard.activity(/ActivityGetAllSMS/)	or
					androguard.activity(/ActivitySendSMS/)	or
					androguard.activity(/ActivityPermission/)
			  	)
			  	and
			  	(
				  	androguard.filter("android.intent.action.BOOT_COMPLETED") and
					androguard.filter("android.intent.action.DREAMING_STOPPED") and
					androguard.filter("android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE") and
					androguard.filter("android.intent.action.PACKAGE_ADDED") and
					androguard.filter("android.intent.action.PACKAGE_REMOVED") and
					androguard.filter("android.intent.action.QUICKBOOT_POWERON") and
					androguard.filter("android.intent.action.SCREEN_ON") and
					androguard.filter("android.intent.action.SEND") and
					androguard.filter("android.intent.action.SENDTO") and
					androguard.filter("android.intent.action.USER_PRESENT") and
					androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and
					androguard.filter("android.net.wifi.WIFI_STATE_CHANGED") and
					androguard.filter("android.provider.Telephony.SMS_DELIVER") and
					androguard.filter("android.provider.Telephony.SMS_RECEIVED") and
					androguard.filter("android.provider.Telephony.WAP_PUSH_DELIVER") and
					androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON")
				)
			)
			and
			(
				droidbox.written.filename(/app_DynamicOptDex\/[a-zA-Z]{2,10}.json/) or
				droidbox.written.filename(/shared_prefs\/SharedData.xml/) or
				droidbox.read.filename(/shared_prefs\/SharedData.xml/)
			)
		)
		
}
