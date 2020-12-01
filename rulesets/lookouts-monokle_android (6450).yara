/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Tubi
    Rule name: Lookout's Monokle_android
    Rule id: 6450
    Created at: 2020-03-08 11:27:42
    Updated at: 2020-03-09 10:31:36
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Lookout_Monokle_Android
// https://www.lookout.com/documents/threat-reports/lookout-discovers-monokle-threat-report.pdf

{
 meta:
   description = "Rule for Monokle Android samples. Configuration information suggests actor has a presence in Russia. Campaigns appear highly targeted."
   auth = "Flossman - SecInt <threatintel@lookout.com>"
   date = "2018-04-24"
   version = "1.0"
 
 strings: 
 $dex_file = { 64 65 78 0A 30 33 35 00 }
 $seq_security_update = { 00 20 4C 63 6F 6D 2F 73 79 73 74 65 6D 2F 73 65 63 75 72 69 74 79 5F 75 70 64 61 74 65
2F 41 70 70 3B 00 }
 $str_recs_file = "recs233268"
 $str_sound_rec_fname = "nsr516336743.lmt"
 $str_nexus_6_recording = "Nexus 6 startMediaRecorderNexus"
 $str_next_connect_date_fname = "lcd110992264.d"
 $str_app_change_broadcast = "com.system.security.event.APP_CHANGE_STATE"
 $str_remove_presence_flag_1 = "Android/data/serv8202965/log9208846.txt"
 $str_remove_presence_flag_2 = "Android/data/serv8202965"
 $str_user_dict = "/data/local/tmp/5f2bqwko.tmp"
 $seq_failed_to_read_firefox = { 46 61 69 6C 65 64 20 74 6F 20 72 65 61 64 20 46 69 72 65 66 6F 78 20 42 72 6F 77 73 65 72 20 62 6F 6F 6B 6D 61 72 6B 73 20 66 72 6F 6D 20 }
 $str_firefox_temp_default = "/data/local/tmp/fegjrexkk.tmp"
 $seq_failed_to_read_samsung = { 46 61 69 6C 65 64 20 74 6F 20 72 65 61 64 20 53 61 6D 73 75 6E 67 20 42 72 6F 77 73 65 72 20 62 6F 6F 6B 6D 61 72 6B 73 20 66 72 6F 6D 20 }
 $str_get_bookmarks_api_log = "getBookmarksFromSBrowserApi23"
 $str_samsung_browser_temp = "/data/local/tmp/swbkxmsi.tmp"
 $str_samsung_browser_temp_2 = "/data/local/tmp/swnkxmsh.tmp"
 
 condition:
 $dex_file and (any of ($seq*) or any of ($str*))
}
