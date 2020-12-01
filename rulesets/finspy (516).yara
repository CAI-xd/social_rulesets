/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jrascon
    Rule name: FinSpy
    Rule id: 516
    Created at: 2015-05-26 10:32:46
    Updated at: 2015-08-06 15:20:09
    
    Rating: #0
    Total detections: 364
*/

rule FinSpy
{
	meta:
		description = "FinSpy"
		info = "http://maldr0id.blogspot.com.es/2014/10/whatsapp-with-finspy.html"

	strings:
		$a = "4j#e*F9+Ms%|g1~5.3rH!we"

	condition:
		$a
}
