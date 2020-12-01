/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Packers
    Rule id: 826
    Created at: 2015-09-14 13:12:08
    Updated at: 2017-06-07 09:50:12
    
    Rating: #0
    Total detections: 130859
*/

rule pChaosVMP : Packers
{
	meta:
		description = "Nagapt (chaosvmp)"
		Website = "http://www.nagain.com"

	strings:
		$a = "chaosvmp"
		$b = "ChaosvmpService"

	condition:
		any of them
}
rule pLIAPP : Packers
{
	meta:
		description = "LIAPP"
		Website = "https://liapp.lockincomp.com"

	strings:
		$a = "LiappClassLoader"
		$b = "LIAPPEgg"
		$c = "LIAPPClient"

	condition:
		any of them
}
rule pNqShield : Packers
{
	meta:
		description = "NqShield"
		Website = "http://shield.nq.com"

	strings:
		$a = "NqShield"
		$b = "libnqshieldx86"
		$c = "LIB_NQ_SHIELD"

	condition:
		any of them
}
rule pBangcleSecApk : Packers
{
	meta:
		description = "Bangcle (SecApk)"
		Website = "http://www.bangcle.com"

	strings:
		$a = "libsecexe.x86"
		$b = "libsecmain.x86"
		$c = "SecApk"
		$d = "bangcle_classes"		

	condition:
		any of them
}
rule pTencent : Packers
{
	meta:
		description = "Tencent"
		Website = ".."

	strings:
		$a = "TxAppEntry"
		$b = "StubShell"

	condition:
		all of them
}
rule pAli : Packers
{
	meta:
		description = "Ali"
		Website = "http://jaq.alibaba.com"

	strings:
		$a = "mobisecenhance"
		$b = "StubApplication"

	condition:
		all of them
}
