/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Shuanet_cromo
    Rule id: 1582
    Created at: 2016-07-06 14:28:15
    Updated at: 2016-07-06 14:41:03
    
    Rating: #0
    Total detections: 0
*/

rule shuanet : from_cromosome
{
	meta:
		description = "This rule detects shuanet aggresive malware"
		sample = "created with the help of cromosome.py"

	strings:
		$a = "android.permission.ACCESS_FINE_LOCATION"
		$b = "Lcom/freshui/dextamper/MainActivity"
		$c = "android.permission.RECEIVE_BOOT_COMPLETED"
		$d = "Lorp/frame/shuanet/abs/DataReciver"
		$e = "SHA1-Digest: vYhWz0BWI6qxF2Yy/kAhIUaP5M8="
		$f = "/tmp/ndk-user/tmp/build-stlport/ndk/sources/cxx-stl/gabi++/src/dynamic_cast.cc"
		$g = "com.boyaa.push.NotifyCenter"
		$h = "libcrypt.so"

	condition:
		all of them
	
		
}
