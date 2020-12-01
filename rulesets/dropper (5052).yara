/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: Dropper
    Rule id: 5052
    Created at: 2018-11-09 11:11:34
    Updated at: 2019-06-24 10:36:14
    
    Rating: #0
    Total detections: 142
*/

import "androguard"
import "file"
import "cuckoo"


rule anubis3: Dropper
{
	condition:
	  androguard.permission(/READ_EXTERNAL_STORAGE/) and
	  androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
	  androguard.permission(/REQUEST_INSTALL_PACKAGES/) and
	  androguard.permission(/INTERNET/) and
	  androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
	  androguard.permissions_number < 10
}
