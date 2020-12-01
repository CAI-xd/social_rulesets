/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Trojan.Gen-FakeApp
    Rule id: 5708
    Created at: 2019-07-10 03:37:13
    Updated at: 2019-07-24 22:11:13
    
    Rating: #1
    Total detections: 402
*/

import "androguard"


// Try to detect fake apps that are not officially signed



rule Chrome : fake
{
	condition:
		(
		androguard.app_name(/^Chr[o0]me$/i) or
		androguard.package_name(/com.chrome/) or
		androguard.package_name(/com.android.chrome/)
		) and not (
		androguard.certificate.sha1("38918A453D07199354F8B19AF05EC6562CED5788") or
		androguard.certificate.sha1("D3CC1758A154EB7DD9FFBE5295016733C9682161")
		)
}



rule Discord : fake
{
	condition:
		(
		androguard.app_name(/^D[il1]sc[o0]rd$/i) or
		androguard.package_name(/com.discord/)
		) and not (
		androguard.certificate.sha1("B07FC6AECCD21FCBD40543C85112CAFE099BA56F")
		)
}



rule Facebook : fake
{
	condition:
		(
		androguard.app_name(/^Faceb[o0][o0]k$/i) or
		androguard.package_name(/com.facebook/)
		) and not (
		androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9") or
		androguard.certificate.sha1("7BA7EFE97151AFEB57103266B1200D85A805D7D6")
		)
}



rule Facebook_Lite : fake
{
	condition:
		(
		androguard.app_name(/^Faceb[o0][o0]k[ ]?L[il1]te$/i) or
		androguard.app_name(/^L[il1]te$/i) or
		androguard.package_name(/com.facebook.lite/)
		) and not (
		androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9")
		)
}



rule Google_Apps : fake
{
	condition:
		(
		androguard.package_name(/com.google/) or
		androguard.package_name(/com.android.google/)
		) and not (
		androguard.certificate.sha1("38918A453D07199354F8B19AF05EC6562CED5788") or
		androguard.certificate.sha1("24BB24C05E47E0AEFA68A58A766179D9B613A600") or
		androguard.certificate.sha1("0980A12BE993528C19107BC21AD811478C63CEFC") or
		androguard.certificate.sha1("203997BC46B8792DC9747ABD230569071F9A0439") or
		androguard.certificate.sha1("1F387CB25E0069EFCA490ADE28C060E09D37DD45") or
		androguard.certificate.sha1("9FA50D00B0F4BDAA5D8F371BEA982FB598B7E697") or
		androguard.certificate.sha1("EE3E2B5D95365C5A1CCC2D8DFE48D94EB33B3EBE") or
		androguard.certificate.sha1("26710BDB08F6463B1F5842E2775169E31DD07301")
		)
}



rule Instagram : fake
{
	condition:
		(
		androguard.app_name(/^[Il1]nstagram$/i) or
		androguard.package_name(/com.instagram/)
		) and not (
		androguard.certificate.sha1("C56FB7D591BA6704DF047FD98F535372FEA00211")
		)
}



rule Telegram : fake
{
	condition:
	(
	androguard.app_name(/^Telegram$/i) or
	androguard.package_name(/org.telegram.messenger/)
	) and not (
	androguard.certificate.sha1("9723E5838612E9C7C08CA2C6573B6026D7A51F8F")
	)
}



rule Twitter : fake
{
	condition:
	(
	androguard.app_name(/^Tw[il1]tter$/i) or
	androguard.package_name(/com.twitter/)
	) and not (
	androguard.certificate.sha1("40F3166BB567D3144BCA7DA466BB948B782270EA")
	)
}



rule WhatsApp : fake
{
	condition:
		(
		androguard.app_name(/^What[']?s[ ]?App$/i) or
		androguard.package_name(/com.whatsapp/)
		) and not (
		androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
		)
}
