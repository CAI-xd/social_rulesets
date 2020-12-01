/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: sandoja
    Rule name: New Ruleset
    Rule id: 2789
    Created at: 2017-05-27 21:32:58
    Updated at: 2017-05-27 21:37:08
    
    Rating: #0
    Total detections: 69
*/

rule Android_BANKER_JSM

{
        meta:
                description = "Esta regla detecta Malware Tipo Banker SlempoService"

        strings:
                $a = "Lorg/slempo/service/MessageReceiver" wide ascii
                $b = "Lorg/slempo/service/MyApplication" wide ascii
                $c = "*Lorg/slempo/service/MyDeviceAdminReceiver" wide ascii
                $d = "Lorg/slempo/service/SDCardServiceStarter" wide ascii
                $e = "#Lorg/slempo/service/ServiceStarter" wide ascii

        condition:
                $a or $b or $c or $d or $e
				}
