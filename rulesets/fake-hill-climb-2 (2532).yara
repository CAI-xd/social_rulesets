/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Fake hill climb 2
    Rule id: 2532
    Created at: 2017-04-23 02:00:27
    Updated at: 2017-04-23 02:00:41
    
    Rating: #0
    Total detections: 77
*/

import "androguard"

rule Fake_Hill_Climb2
{
  meta:
      Author = "https://twitter.com/SadFud75"
      Info = "Detection of fake hill climb racing 2 apps"
  condition:
      androguard.app_name("Hill Climb Racing 2") and not androguard.certificate.sha1("F0FDF0136D03383BA4B2BE81A14CD4B778FB1F6C")
}
