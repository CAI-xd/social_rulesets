/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: vsoft
    Rule name: New Ruleset
    Rule id: 1317
    Created at: 2016-03-29 01:39:41
    Updated at: 2016-03-29 01:40:56
    
    Rating: #0
    Total detections: 9736228
*/

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


rule android_meterpreter
{
    meta:
        author="73mp74710n"
        ref = "https://github.com/zombieleet/yara-rules/blob/master/android_metasploit.yar"
        comment="Metasploit Android Meterpreter Payload"
        
    strings:
	$checkPK = "META-INF/PK"
	$checkHp = "[Hp^"
	$checkSdeEncode = /;.Sk/
	$stopEval = "eval"
	$stopBase64 = "base64_decode"
	
    condition:
	any of ($check*) or any of ($stop*)
}
