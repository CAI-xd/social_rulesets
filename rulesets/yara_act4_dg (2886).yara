/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: gutylo3323
    Rule name: YARA_Act4_DG
    Rule id: 2886
    Created at: 2017-05-31 17:20:11
    Updated at: 2017-05-31 17:21:31
    
    Rating: #0
    Total detections: 36
*/

rule YARA_Act4_DG

{
	meta:
		description = "Esta regla detecta Malware de Postbank FinanzAssistent"

	strings:
		$a = "#intercept_sms_start" wide ascii
		$b = "#intercept_sms_stop" wide ascii
		$c = "Lorg/slempo/service/Main" wide ascii
		$d = "Lorg/slempo/service/a/" wide ascii
		$e = "com.slempo.service.activities" wide ascii
		$f = /com.slempo.service/ nocase
		
		

	condition:
		$c and ($a or $b or $d or $e or $f)
		}
