/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_triada_20180305
    Rule id: 4252
    Created at: 2018-03-05 01:34:15
    Updated at: 2018-03-05 01:46:19
    
    Rating: #0
    Total detections: 28
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "https://vms.drweb.com/virus/?_is=1&i=15503184"
		sample = ""

	strings:
		$a = "cf89490001"
		$b = "droi.zhanglin"
		$c = "configppgl"

	condition:
		$a or
		$b or
		$c
		
}
