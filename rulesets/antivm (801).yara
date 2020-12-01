/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: AntiVM
    Rule id: 801
    Created at: 2015-08-26 18:52:32
    Updated at: 2015-08-29 17:48:53
    
    Rating: #0
    Total detections: 2434908
*/

rule AntiVM
{
	meta:
		description = "This rule detects any application that checks VM environment"

	strings:
		$a = /emulator/i
		$b = /goldfish/i
		$c = "DEVICE_ID_EMULATOR"
		$e = "X11 terminal emulator"
		$f = "com/google/android/gms/internal"
		$g = "Only emulators with Google APIs include Google Play Services"
		$h = "com/google/android/gms/ads"
		$i = "com/mixpanel/android/viewcrawler/ViewCrawler$LifecycleCallbacks"

	condition:
		($a or $b or $c) and not ($e or $f or $g or $h or $i)
}
