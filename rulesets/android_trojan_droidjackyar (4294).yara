/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ransombleed
    Rule name: Android_Trojan_Droidjack.yar
    Rule id: 4294
    Created at: 2018-03-27 10:57:47
    Updated at: 2018-03-27 11:00:31
    
    Rating: #-2
    Total detections: 529
*/

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.
	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Trojan_Droidjack
{
meta:
author = "https://twitter.com/SadFud75"
condition:
androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}
