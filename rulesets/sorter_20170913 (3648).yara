/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: Sorter_20170913
    Rule id: 3648
    Created at: 2017-09-22 06:27:11
    Updated at: 2017-09-27 01:14:53
    
    Rating: #0
    Total detections: 35
*/

import "androguard"
import "file"
import "cuckoo"


rule sorter : official
{
	condition:
		cuckoo.network.dns_lookup(/datace/) or
		cuckoo.network.dns_lookup(/www.mmmmmm/) or 
		cuckoo.network.dns_lookup(/fb.vi/) or 
		cuckoo.network.http_request(/cgi-bin-py\/ad_sdk\.cgi/) or
		cuckoo.network.http_request(/\.zpk/) or
		cuckoo.network.http_request(/\.ziu/) or
		cuckoo.network.http_request(/\/Load\/regReportService/) or 
		cuckoo.network.http_request(/\/Load\/regService/)
}
