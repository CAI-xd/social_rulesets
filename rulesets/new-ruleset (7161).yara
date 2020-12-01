/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: teundemast01
    Rule name: New Ruleset
    Rule id: 7161
    Created at: 2020-11-07 13:43:18
    Updated at: 2020-11-07 14:08:30
    
    Rating: #0
    Total detections: 0
*/

rule Cajino: official
{
	meta:
		Author = "Teun de Mast"
		Studentnumber = "2656566"
		Description = "A rule to detect Cajino (remote controlled spyware)"
		Reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"

	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE"
		$b = "com.baidu.android.pushservice.action.RECEIVE"
		$c = "com.baidu.android.pushservice.action.notification.CLICK"
		$d = "업데이트"
		$e = "새버전으로 업데이트 합니다 "
		$f = "application/vnd.android.package-archive"

	condition:
		$a and $b and $c and $d and $e and $f
		
}
