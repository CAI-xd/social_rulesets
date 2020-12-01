/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dawson1981
    Rule name: iBank
    Rule id: 2820
    Created at: 2017-05-29 21:42:13
    Updated at: 2017-05-29 21:59:02
    
    Rating: #0
    Total detections: 25
*/

rule Android_Malware : iBank
{
	meta:
		description = "iBank"
	
		
	strings:
		// Generic android
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		// iBanking related
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
}
