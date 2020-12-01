/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: imm17
    Rule name: New Ruleset
    Rule id: 2888
    Created at: 2017-05-31 18:17:29
    Updated at: 2017-05-31 18:45:10
    
    Rating: #0
    Total detections: 0
*/

rule samplep4
{
	meta:
		description=”samplepract”
	string:
		$a=”org/slempo/service”
		$b=”http://185.62.188.32/app/remote”
		$c=”Landroit/telephony/SmsManager”
		$d=”intercept_sms_start”
	Condition:
		$a and ($b or $c $d )
}
