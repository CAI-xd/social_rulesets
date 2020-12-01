/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: MRDekeijzer
    Rule name: New Ruleset
    Rule id: 7210
    Created at: 2020-11-09 19:46:25
    Updated at: 2020-11-09 19:47:30
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
    meta:
		author = "Matthijs en Nils"
		date = "10/11/2020"
		description = "This is a YARA rule for Cyber Security APK 1"
    strings:
        $a = "http://www.whoishostingthis.com/tools/user-agent/"
        $b = "android.permission.GET_TASKS"
        $c = "android.permission.INTERNET"
        $d = "android.permission.WRITE_EXTERNAL_STORAGE"
        $e = "android.permission.READ_PHONE_STATE"
        $f = "android@android.com"
	 	$g = "note"

    condition:
        $a and $b and $c and $d and $e and $f and $g
}
