/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ransombleed
    Rule name: Xafecopy
    Rule id: 4297
    Created at: 2018-03-27 11:01:03
    Updated at: 2018-03-28 08:36:35
    
    Rating: #0
    Total detections: 80
*/

rule Xafecopy
{
	meta:
		author = "Ransombleed"
		description = "Xafecopy detection rule"
	strings:
        $a =  "assets/chazhaoanniu.js"
		$a2 = "assets/chuliurl.js"
		$a3 = "assets/monidianji.js"
		$a4 = "assets/shuruyzm.js"
        $b =  "//Your system is optimizing"
        $b2 = "Congratulations, you have a chance to use the world's popular battery tool."
        $b3 = "Clean Up Assistant is a small, stylish, elegant application that can help you focus on the current battery charge percentage of your circumstances Android device, and even can be used as energy saving device."

       
	condition:
		1 of ($a*) or 2 of ($b*)
}
