/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cnag
    Rule name: Repackage using quickshortcuu
    Rule id: 7346
    Created at: 2020-11-17 01:04:45
    Updated at: 2020-11-17 01:21:18
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule quickshortcuu
{
	meta:
		description = "rule to detect a repackage of quickshortcut using the quickshortcuu name"
		sample = "fc305e74aa702b7cae0c13369abfe51e0556198cf96522c5782e06cce9a19edf"
		
	strings:
		$a = "com.sika524.android.quickshortcuu"
		$b = { 63 6f 6d 2e 73 69 6b 61 35 32 34 2e 61 6e 64 72 6f 69 64 2e 71 75 69 63 6b 73 68 6f 72 74 63 75 75 }

	condition:
		($a or $b) and
		androguard.app_name("QuickShortcutMaker")
}
