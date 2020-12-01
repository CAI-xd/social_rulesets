/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Username5001250012
    Rule name: antiWipeLocker
    Rule id: 7159
    Created at: 2020-11-07 13:37:12
    Updated at: 2020-11-07 17:25:51
    
    Rating: #0
    Total detections: 0
*/

rule antiWipeLocker
{
	meta:
		description = "Rule against the antiWipeLocker malware"

	strings:
		$preDeletion = "wipeMemoryCard" nocase
		$hideApp = "HideAppFromLauncher" nocase
		$doubleCheck0 = "setComponentEnabledSetting(this.getComponentName(), 2, 1);"
		$doubleCheck1 = "setComponentEnabledSetting(this.getComponentName(), 2, DONT_KILL_APP);"
		$doubleCheck2 = "setComponentEnabledSetting(this.getComponentName(), COMPONENT_ENABLED_STATE_DISABLED, 1);"
		$doubleCheck3 = "setComponentEnabledSetting(this.getComponentName(), COMPONENT_ENABLED_STATE_DISABLED, DONT_KILL_APP);"

	condition:
		$preDeletion or ($hideApp and ($doubleCheck0 or $doubleCheck1 or $doubleCheck2 or $doubleCheck3))
		
}
