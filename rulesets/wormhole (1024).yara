/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Wormhole
    Rule id: 1024
    Created at: 2015-11-18 20:47:52
    Updated at: 2015-11-18 20:56:58
    
    Rating: #5
    Total detections: 106654
*/

import "androguard"

rule wormHole
{
	meta:
		description = "Wormhome vulnerability found in com.qihoo.secstore con GPlay. After app launch, a SimpleWebServer service is called listening to 0.0.0.0:38517. It uses yunpan to upload files and get a 360 domain. App protected by proguard."
	strings:
		$a = "/getModel0" 
		$b = "/in" // download and install apk
		$c = "/openPage" // Open URL
		$d = "/openActivity" // Launch activity
		$e = "/isAppInstalled" // Check app existance
		$f = ".360.cn" 
		$g = ".so.com" 
		$h = ".qihoo.net"
		$i = ".gamer.cn"
		// 360 domains host through yunpan clod storage (anyone can upload files here)
	condition:
		($a or $b or $c or $d or $e) and ($f or $g or $h  or $i)
		
		
		
}
