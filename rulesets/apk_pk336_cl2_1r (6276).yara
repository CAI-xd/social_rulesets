/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: PerikiyoXD
    Rule name: APK_PK336_CL2_1R
    Rule id: 6276
    Created at: 2020-01-04 05:54:58
    Updated at: 2020-01-04 06:03:06
    
    Rating: #1
    Total detections: 197
*/

rule APK_PK336_CL2_1R 
{
	meta:
		description = "2 classes, 1 generated R class and all those strings... Has payload 100% guaranteed"
		sample = "d941a4f11ecaf9472692d0707d126ee085dbd84af699e21cfab07db16dbbc992"
		sample = "e69c1b28584a9abadb7cd6d07d277de071c354c5f02f973fe99c3eb6c5f01d5b"

	strings:
		$ = "android.app.ActivityThread$ProviderClientRecord"
		$ = "android.app.ActivityThread$AppBindData"
		$ = "android.content.ContentProvider"
		$ = "android.app.ActivityThread"
		$ = "android.app.LoadedApk"
		$ = "mInitialApplication"
		$ = "mLocalProvider"
		$ = "mClassLoader"
		$ = "mProviderMap"
		$ = "mContext"
		$ = "jar"
	condition:
		all of them
}
