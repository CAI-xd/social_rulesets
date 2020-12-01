/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kaka
    Rule name: Ilovetv
    Rule id: 7150
    Created at: 2020-11-06 12:11:36
    Updated at: 2020-11-06 12:13:03
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule loveads
{
    meta:
   		description = "APK contains malware of all sorts, adware/trojan"


    strings:
        $a = "https://e.crashlytics.com/spi/v2/events"
        $b = "https://settings.crashlytics.com/spi/v2/platforms/android/apps/%s/settings"
      
    condition:
        $a and $b
		}
