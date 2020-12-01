/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dawson1981
    Rule name: Regla banker 2
    Rule id: 2824
    Created at: 2017-05-29 21:57:57
    Updated at: 2017-05-29 21:58:39
    
    Rating: #0
    Total detections: 246
*/

rule sample

{
	meta:
		description = "sample"
	strings:
		$a = "185.62.188.32"
		$b = "TYPE_SMS_CONTENT"
		$c = "getRunningTasks"

	condition:
		$b and ($a or $c)
}
