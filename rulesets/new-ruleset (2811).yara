/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: sandoja
    Rule name: New Ruleset
    Rule id: 2811
    Created at: 2017-05-29 16:41:22
    Updated at: 2017-05-29 16:41:32
    
    Rating: #0
    Total detections: 140
*/

rule Android_BANKER_JSM

{
	meta:
		description = "Esta regla detecta Malware Tipo Banker SlempoService "

	strings:
		$a = "Lorg/slempo/service/MessageReceiver" wide ascii
		$b = "Lorg/slempo/service/MyApplication" wide ascii
		$c = "*Lorg/slempo/service/MyDeviceAdminReceiver" wide ascii
		$d = "Lorg/slempo/service/SDCardServiceStarter" wide ascii
		$e = "org/slempo/service" nocase
		$f = /com.slempo.service/ nocase
		$g = "#Lorg/slempo/service/ServiceStarter" wide ascii

	condition:
		$a or $b or $c or $d or $e or $f or $g
		}
