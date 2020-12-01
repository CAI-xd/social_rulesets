/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: PhoneCaller
    Rule id: 901
    Created at: 2015-10-08 20:38:18
    Updated at: 2015-10-08 20:38:40
    
    Rating: #0
    Total detections: 204
*/

import "droidbox"

rule PhoneCall
{
	meta:
		description = "Phone Caller"
		
	condition:
		droidbox.phonecall(/./)
}
