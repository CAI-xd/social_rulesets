/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: epicgamer69
    Rule name: New Ruleset
    Rule id: 7196
    Created at: 2020-11-09 14:43:09
    Updated at: 2020-11-16 15:07:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"


rule zooking : official
{
	meta:
		description = "This rule detects Zooking theme"
		sample = "8d40ecebf2d2288ba8db4442701eb7be03c28149033742491bd5373f612474ec"

	strings:
		$a = "com.zzadsdk.sdk.activity.RewardedVideo"
		$b = "http://openbox.mobilem.360.cn/third/download?downloadUrl=http%3A%2F%2Fshouji.360tpcdn.com%2F180516%2F4e09ba8f237b7ecc9a229b05e420fd88%2Fcom.zhima.wszb_450.apk&softId=3981200&from=ivvi&pname=com.zhima.wszb"
		$c =  "http://adc.vanmatt.com/pk/u/c"
		$d = "https://www.starbucks.com.cn/menu/#lto-items" 
		$e = "http://lockscreen.zookingsoft.com:8888/LockScreen/LoadBalancing"

	condition:
		androguard.certificate.sha1("5cf396ef252bc129affdb6c6f6915461bfc36205") and
		$a and $b and $c and $d and $e
		
}
