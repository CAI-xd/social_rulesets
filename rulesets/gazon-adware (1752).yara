/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Gazon adware
    Rule id: 1752
    Created at: 2016-08-19 19:50:11
    Updated at: 2016-08-19 19:51:35
    
    Rating: #0
    Total detections: 0
*/

rule gazon 
{
	meta:
		description = "This rule detects gazon adware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "ads-184927387.jar"

	condition:
		$a
		
}
