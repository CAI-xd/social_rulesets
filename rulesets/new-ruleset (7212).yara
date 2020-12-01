/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: MRDekeijzer
    Rule name: New Ruleset
    Rule id: 7212
    Created at: 2020-11-09 19:51:11
    Updated at: 2020-11-09 19:56:23
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule CAJINO {
meta:
  author 		= "Matthijs en Nils"
  date 			= "10/11/2020"
  description 	= "This is a YARA rule for Cajino"
    
strings:
  $register = "getApplicationContext()"
  $phone 	= "getSystemService(\"phone\")"
  $feature1 = "getContact"
  $feature2 = "getCallLog"
  $feature3 = "getMessage"
  $feature4 = "getLocation"
  $feature5 = "sendTextMessage"
  $feature6 = "getPhoneInfo"
  $feature7 = "listFileByPath"
  $feature8 = "recorder.prepare()"
  $feature9 = "installApk"
 
condition:
  $register and $phone and 1 of ($feature*)
}
