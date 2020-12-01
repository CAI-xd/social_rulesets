/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Christie
    Rule name: New Ruleset
    Rule id: 7202
    Created at: 2020-11-09 15:26:28
    Updated at: 2020-11-09 15:34:09
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Rule to detect Trojan Spy"
		sample = "4bc7089a1bb6ee42a5c362e5a85429d3a57f6b21eb1272630fc27542f3c40b78"

	strings:
		$a = "http://pc.qq.com/"

	condition:
		androguard.package_name("com.dadada ") and
		androguard.app_name("SystemConfigure") and
		androguard.activity(/com.dadada.MainActivity/) and
		androguard.permission(/android.permission.CHANGE_NETWORK_STATE/) and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.WRITE_SYNC_SETTINGS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCES_FINE_LOCATION/) and
		androguard.permission(/android.permission.INTERACT_ACROSS_USERS_FULL/) and
		androguard.permission(/android.permission.WRITE_CALL_LOG/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.READ_HISTORY_BOOKMARKS/) and
		androguard.permission(/android.permission.BIND_JOB_SERVICE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.SET_TIME_ZONE/) and
		androguard.permission(/android.permission.RECIEVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.VIBRATE/) and
		androguard.permission(/android.permission.AUTHENTICATE_ACCOUNT/) and
		androguard.permission(/android.permission.PERMISSION_NAME/) and
		androguard.permission(/android.permission.WRITE_SETTINGS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.MODIFY_AUDIO_SETTINGS/) and
		androguard.permission(/android.permission.GET_ACCOUNTS_PRIVILEGED/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.ACCES_PROVIDER/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.RECIEVE_SMS/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.MOUNT_UNMOUNT_FILESYSTEMS/) and
		androguard.permission(/android.permission.GET_ACCOUNTS/) and
		androguard.certificate.sha1("1481FAED0497292AFE5F9628EEF228448AD8E70A") and
		androguard.url(/https://koodous.com\apks\4bc7089a1bb6ee42a5c362e5a85429d3a57f6b21eb1272630fc27542f3c40b78/) and
		not file.md5(/3f62cc4ba50b27e762cb8f21f38495cd/) and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
}
