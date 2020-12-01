/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSSender
    Rule id: 1302
    Created at: 2016-03-18 14:42:25
    Updated at: 2016-03-24 09:40:05
    
    Rating: #0
    Total detections: 982
*/

rule SMSSender
{
	meta:
		description = "This rule detects a type of SMSSender trojan"
		sample = "2b69cd97c90080dcdcd2f84ef0d91b1bfd858f8defd3b96fbcabad260f511fe7"
		search = "package_name:com.nys.mm"

	strings:
		$json_1 = "\"tn\":\"%s\",\"user\":\"%s\",\"locale\":\"%s\",\"terminal_version\":\"%s\",\"terminal_resolution\":\"%s\""
		$json_2 = "{\"v\":\"%s\",\"cmd\":\"sms\",\"params\":{\"first_pay_flag\":\"%s\",%s}}"
		$json_3 = "\"IsFetchSms\":\"1\",\"SoundTime\":\"10\",\"LbsTime\":\"3000\",\"SmsPattern\":"
		$fail_msg = "Fail to construct message"
		$code = "9AEKIJM?"
		$func_name = "setDiscount"

	condition:
		all of them
		
}
