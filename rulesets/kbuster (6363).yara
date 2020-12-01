/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jackbox
    Rule name: KBuster
    Rule id: 6363
    Created at: 2020-02-07 09:16:47
    Updated at: 2020-10-30 11:40:55
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "cuckoo"
import "droidbox"


rule KBuster
{
	meta:
		description = "KBuster sms stealer malware"
		
	condition:
		droidbox.written.data(/.PC_UpThread/i) and
		droidbox.written.data(/.PC_SMobs/i) and
		droidbox.written.data(/.PC_CallRc/i) and
		droidbox.written.data(/PG_CO.bserver/i) or
		droidbox.written.filename(/contacts.dat/i)
		
}
