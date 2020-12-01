/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: darbong
    Rule name: New Ruleset
    Rule id: 5553
    Created at: 2019-05-22 05:41:44
    Updated at: 2019-05-22 06:38:36
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule sauronlocker_android_app
{
    meta:
        description = "Sauron Locker"
        package_name = "com.ins.screensaver"
        sample = "a145ca02d3d0a0846a6dde235db9520d97efa65f7215e7cc134e6fcaf7a10ca8,09192d3095b7708378d4578d5c331cda7b9125d406b63d55b6855f774bbfc41f"

    strings:
        $str1 = "attach.php?uid="
        $str2 = "&os="
        $str3 = "&model="
        $str4 = "&permissions=0&country="
        $str5 = "encrypted"
        $url1 = "http://timei2260.myjino.ru"
        $url2 = "http://d91976z0.beget.tech"

    condition:
        androguard.package_name("com.ins.screensaver") and
        androguard.permission(/android.permission.SET_WALLPAPER/) and
        androguard.service(/com.ins.screensaver.services.CheckerService/) and
        (all of ($str*)) or (1 of ($url*))
}
