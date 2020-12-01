/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xoreax
    Rule name: Spy.Banker
    Rule id: 1614
    Created at: 2016-07-13 06:32:13
    Updated at: 2016-07-13 06:39:45
    
    Rating: #-1
    Total detections: 30
*/

import "androguard"
import "file"
import "cuckoo"


rule Spy_Banker
{
	meta:
		description = "This rule detects the Spy.Banker.BQ"
		sample = "d715e0be04f97bb7679dec413ac068d75d0c79ce35c3f8fa4677fc95cefbfeb8"

	strings:
		$a = "#BEBEBE"
		$b = "Remove MMS"
		$c = "Enter credit card"
		$d = "SELECT  * FROM smsbase"
		$e = "szCardNumverCard"
		$f = "[admintext]"
		
	condition:
		all of them
		
}
