/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: PerikiyoXD
    Rule name: DTCLoader v1.0
    Rule id: 6272
    Created at: 2020-01-03 15:24:22
    Updated at: 2020-01-05 03:54:27
    
    Rating: #0
    Total detections: 1652
*/

rule DTCLoader_Strngs : DTCLOADER
{
	meta:
		description = "Rule used to catch \"DtcLoader\" app strings, which look like malicious"
	strings:
		$ = "entryRunApplication"
		$ = "q~tb\\u007fyt>q``>QsdyfydiDxbuqt"
		$ = "wudCicdu}S\\u007f~duhd"
		$ = "sebbu~dQsdyfydiDxbuqt"
		$ = "\\u786e\\u5b9a"
		$ = "libjiagu"
	condition:
		all of them
}


rule String_ls_Binary : DTCLOADER
{
	meta:
		description = "String pointing to ls binary"
	strings:
		$ = "/system/bin/ls"
	condition:
		any of them
}
