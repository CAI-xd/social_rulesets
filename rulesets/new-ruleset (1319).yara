/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: vsoft
    Rule name: New Ruleset
    Rule id: 1319
    Created at: 2016-03-29 02:04:07
    Updated at: 2016-03-29 02:05:18
    
    Rating: #0
    Total detections: 0
*/

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule dropper:realshell android {
    meta:
        author = "https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
    strings:
        $b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
    
    condition:
        $b
}
