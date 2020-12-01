/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mquintans
    Rule name: Slempo
    Rule id: 1290
    Created at: 2016-03-14 14:55:40
    Updated at: 2016-03-14 14:56:01
    
    Rating: #0
    Total detections: 307
*/

import "androguard"



rule slempo : package
{
  meta:
    description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
    sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"

  condition:
    androguard.package_name("org.slempo.service")
}
