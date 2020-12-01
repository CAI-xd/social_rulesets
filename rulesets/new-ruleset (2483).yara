/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fernandocuervo
    Rule name: New Ruleset
    Rule id: 2483
    Created at: 2017-04-18 14:08:52
    Updated at: 2017-04-18 14:09:18
    
    Rating: #0
    Total detections: 122
*/

rule banking
{
	meta:
		description = "This rule detects is to detect a type of banking malware"
		sample = "33b1a9e4a1591c1a39fdd5295874e365dbde9448098254a938525385498da070"

	strings:
		$a = "cmVudCYmJg=="
		$b = "dXNzZCYmJg=="

	condition:
		all of them
		
}

rule marcher2
{
	strings:
		$a = "HDNRQ2gOlm"
		$b = "lElvyohc9Y1X+nzVUEjW8W3SbUA"
	condition:
		all of them
		
}

rule marcher3
{
	meta:
		sample1 = "087710b944c09c3905a5a9c94337a75ad88706587c10c632b78fad52ec8dfcbe"
		sample2 = "fa7a9145b8fc32e3ac16fa4a4cf681b2fa5405fc154327f879eaf71dd42595c2"
	strings:
		//$a = "vTTVd6htnKr/ZzQJ/VoZbCeDEiA=" Generate FP
		$b = "certificado # 73828394"
		$c = "A compania TMN informa que o vosso sistema Android tem vulnerabilidade"
		
	condition:
		all of them
}
