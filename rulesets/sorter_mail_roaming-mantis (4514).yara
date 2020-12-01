/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_mail_roaming-mantis
    Rule id: 4514
    Created at: 2018-06-09 03:34:59
    Updated at: 2018-06-13 05:33:20
    
    Rating: #0
    Total detections: 697491
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	strings:
		//$ = "mail.smtp.host"
		$ = "whb"
		$="com.epost.psf.sdsi"
		$="com.hanabank.ebk.channel.android.hananbank"
		$="com.ibk.neobanking"
		$="com.kbstar.kbbank"
		$="com.kftc.kjbsmb"
		$="com.ncsoft.lineagem"
		$="com.sc.danb.scbankapp"
		$="com.shinhan.sbanking"
		$="com.smg.spbs"
		$="nh.smart"
		$="com.atsolution.android.uotp2"
		$="com.ncsoft.lineagem19"
		$="com.nexon.axe"
		$="com.nexon.nxplay"
		$="com.webzen.muorigin.google"
		$="com.wooribank.pib.smart"
		$="kr.co.happymoney.android.happymoney"
		$="kr.co.neople.neopleotp"
		$="https://www.baidu.com/p/%s/detail"

	condition:
		any of them
}
