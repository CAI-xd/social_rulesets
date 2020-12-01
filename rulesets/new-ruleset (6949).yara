/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 5h1vang
    Rule name: New Ruleset
    Rule id: 6949
    Created at: 2020-05-26 05:36:08
    Updated at: 2020-08-19 11:34:02
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		author = "Sdesai"
		sample = "df8b64f1e3843b50735d5996bd980981"

	strings:
		
		$hash="SHA1:dda09d19354d25833153d64077cd396c970bb1d4"
		$url="AMStrings:https://www.Spy-datacenter.com/send_data.php"
		$per_1="Permission:android.permission.RECEIVE_SMS"
		$per_2="Permission:android.permission.RECORD_AUDIO"
		
		$str_2="AMStrings:recording_phone"
		$str_3="AMStrings:disable_call_recording"
		$str_4="AMStrings:#takepic"
		$str_5="AMStrings:#recordaudio"
		$str_6="AMStrings:#lockphone"
		$str_7="AMStrings:unlock_phone_pass"
		$str_8="AMStrings:take_pic_front"
		$str_9="android.intent.action.NEW_OUTGOING_CALL"
		$str_10="AMStrings:content://call_log/calls"
		$str_11="AMStrings:content://com.android.chrome.browser/history"
		$str_13="AMStrings:hide_icon"


	condition:
		($hash and $url and $per_1 and $per_2) or (all of ($str_*))
}
