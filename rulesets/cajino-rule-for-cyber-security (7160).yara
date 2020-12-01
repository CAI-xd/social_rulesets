/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: teundemast01
    Rule name: Cajino Rule (for Cyber Security)
    Rule id: 7160
    Created at: 2020-11-07 13:42:14
    Updated at: 2020-11-09 17:42:41
    
    Rating: #0
    Total detections: 0
*/

rule Cajino
{
	meta:
		Authors = "Teun de Mast and Lennard Hordijk"
		Studentnumbers = "respectively: 2656566 and 2716143"
		Description = "A rule to detect Cajino (remote controlled spyware)"
		Reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"
	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE"
		$b = "com.baidu.android.pushservice.action.RECEIVE"
		$c = "com.baidu.android.pushservice.action.notification.CLICK"
		$d = "application/vnd.android.package-archive"

	condition:
		$a and $b and $c and $d
	
}
