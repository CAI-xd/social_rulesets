/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: deedoz
    Rule name: Pot_app_installer
    Rule id: 5870
    Created at: 2019-08-23 09:00:50
    Updated at: 2019-08-23 09:01:16
    
    Rating: #0
    Total detections: 21245
*/

import "androguard"

rule AppInstaller

{
    meta:
	description = "The app installs other apps or at least interested in newly installed Apps"

    condition:
	androguard.filter(/com.android.vending.INSTALL_REFERRER/) or
	androguard.permission(/INSTALL_PACKAGES/)

}
