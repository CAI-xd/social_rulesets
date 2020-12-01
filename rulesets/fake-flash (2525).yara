/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Fake flash
    Rule id: 2525
    Created at: 2017-04-22 10:37:18
    Updated at: 2017-04-23 02:43:54
    
    Rating: #0
    Total detections: 1004
*/

import "androguard"

rule Fake_Flash
{
  meta:
       description = "Detects fake flash apps"
   condition:
       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) //and not
       //(androguard.app_name(/acrobat/) or androguard.app_name(/pdf/))
}
