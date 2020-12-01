/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: DexClassLoader
    Rule id: 3173
    Created at: 2017-07-16 10:47:56
    Updated at: 2017-07-16 10:49:02
    
    Rating: #0
    Total detections: 804714
*/

rule DexClassLoader
{
	meta:
		description = "Ldalvik/system/DexClassLoader;"

	strings:
		$a = "Ldalvik/system/DexClassLoader;"

	condition:
		$a 
		
}
