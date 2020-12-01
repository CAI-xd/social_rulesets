/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: DexClassLoader
    Rule id: 3169
    Created at: 2017-07-15 15:41:35
    Updated at: 2017-07-17 18:30:07
    
    Rating: #0
    Total detections: 777628
*/

rule DexClassLoader
{
	meta:
		description = "DexClassLoader"

	strings:
		$a = "Ldalvik/system/DexClassLoader;"

	condition:
		$a 
}
