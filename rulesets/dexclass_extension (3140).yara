/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yle
    Rule name: Dexclass_extension
    Rule id: 3140
    Created at: 2017-07-14 18:59:39
    Updated at: 2017-07-15 10:36:02
    
    Rating: #0
    Total detections: 996604
*/

import "droidbox"



rule dexclass
{
    condition:
        droidbox.read.filename(/dex/) or droidbox.read.filename(/jar/) or droidbox.read.filename(/apk/)  
}
