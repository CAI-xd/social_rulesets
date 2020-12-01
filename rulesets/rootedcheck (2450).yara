/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mi3security
    Rule name: RootedCheck
    Rule id: 2450
    Created at: 2017-04-12 17:45:00
    Updated at: 2017-04-12 17:54:57
    
    Rating: #0
    Total detections: 1074088
*/

import "androguard"


rule RootedCheck 
{
	meta:
		description = "This rule detects applications checking for/or requiring root access."

	strings:
		$a = "bin/which su"
		$b = "/sbin/su"
		$c = "system/bin/su"
		$d = "bin/which su"
		$e = "Superuser.apk"
		$f = "/system/xbin/su"
		$g = "/data/local/xbin/su"
		$h = "/data/local/bin/su"
		$i = "/system/sd/xbin/su"
		$j = "/system/bin/failsafe/su"
		$k = "/data/local/su"
		$l = "/system/xbin/which"
		$m = "which su"

		
	condition:
		$a or
		$b or
		$c or
		$d or
		$e or
		$f or
		$g or
		$h or
		$i or
		$j or
		$k or
		$l or $m

}
