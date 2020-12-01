/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmiston
    Rule name: harsobh mirror
    Rule id: 4584
    Created at: 2018-06-25 08:34:16
    Updated at: 2018-09-26 23:14:06
    
    Rating: #0
    Total detections: 64
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "harsobh mirror"
	condition:
		androguard.url(/mirror1\.harsobh\.com/)
		
}
