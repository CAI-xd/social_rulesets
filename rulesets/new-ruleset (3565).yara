/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skyline65
    Rule name: New Ruleset
    Rule id: 3565
    Created at: 2017-09-08 13:29:14
    Updated at: 2017-09-08 13:29:19
    
    Rating: #0
    Total detections: 1
*/

rule HummingWhale
{
	meta:
		description = "A Whale of a Tale: HummingBad Returns, http://blog.checkpoint.com/2017/01/23/hummingbad-returns/"
		sample = "0aabea98f675b5c3bb0889602501c18f79374a5bea9c8a5f8fc3d3e5414d70a6"

	strings:
		$ = "apis.groupteamapi.com"
		$ = "app.blinkingcamera.com"
		
	condition:
 		1 of them
		
}
