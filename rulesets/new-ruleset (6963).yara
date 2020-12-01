/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Behroozfar
    Rule name: New Ruleset
    Rule id: 6963
    Created at: 2020-06-09 14:59:11
    Updated at: 2020-06-09 15:14:37
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "droidbox"


rule dynamicAnalysis : qok
{
	condition:
		droidbox.written.filename(/libdexprotector/)
		or droidbox.library(/libdexprotectorasfe90\.so/)
		or droidbox.written.data(/6465780A303335/i)
		or droidbox.read.data(/6465780A303335/i)
}
