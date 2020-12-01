/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_ckservice
    Rule id: 4686
    Created at: 2018-07-25 08:59:25
    Updated at: 2018-08-02 06:43:18
    
    Rating: #0
    Total detections: 37
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$ = "downloader_center_instance"
		$ = "ww_proj"
		$ = "1fa78cfb99fbdb144751ccd9a086e65e"
		$ = "f3c744d950bf70dfc8c7cbcae23f26fa"
		$ = "ck2@13!4"

	condition:
		any of them
		or cuckoo.network.dns_lookup(/xuenya.net/)
		or cuckoo.network.dns_lookup(/os-1253691939.file.myqcloud.com/)
		or androguard.url(/os-1253691939.file.myqcloud.com/)		
}
