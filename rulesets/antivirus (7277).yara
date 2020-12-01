/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: liva
    Rule name: Antivirus
    Rule id: 7277
    Created at: 2020-11-12 15:51:09
    Updated at: 2020-11-12 16:11:38
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Antivirus
{
	strings:
		$a = "http://"
		$b = "http://checkip.amazonaws.com/"
		$c = "http://example.com"
		$d = "http://play.google.com/store/apps/%s?%s"
		$e = "http://vignette2.wikia.nocookie.net/logopedia/images/d/d2/Google_icon_2015.png"
		$f = "http://www.whoishostingthis.com/tools/user-agent/"
		$g = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"
		$h = "https://play.google.com/store/apps/details?id=org.mightyfrog.android."

	condition:
		androguard.package_name("demo.restaurent.ingeniumbd.demorestaurant") or /*This is only the case for the analysed APK, but I want this rule to work for similar APKs as well, so it is an 'or'-statement instead of an 'and'-statement.*/
		androguard.app_name("AVG AntiVirus 2020 for Android Security FREE") or /*This is only the case for the analysed APK, but I want this rule to work for similar APKs as well, so it is an 'or'-statement instead of an 'and'-statement.*/
		androguard.permission(/android.permission.WRITE_EXTERNAL-STORAGE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		$a and $b and $c and $d and $e and $f and $g and $h
}
