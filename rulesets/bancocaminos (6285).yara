/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dieee
    Rule name: BancoCaminos
    Rule id: 6285
    Created at: 2020-01-08 10:43:25
    Updated at: 2020-02-14 11:20:19
    
    Rating: #0
    Total detections: 0
*/

rule bancocam {

	strings:
		$string_1 = /bancocaminos/
		$string_2 = /onboardingcaminos/
		$string_3 = /lineacaminos/
		$string_4 = /onboardingcaminos/
		$string_5 = /caminosontime/
		
	condition:
		any of them
}
