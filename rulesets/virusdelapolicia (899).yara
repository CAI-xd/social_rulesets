/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: VirusDeLaPolicia
    Rule id: 899
    Created at: 2015-10-08 20:36:52
    Updated at: 2015-10-08 20:45:30
    
    Rating: #0
    Total detections: 0
*/

rule virus_de_la_policia
{
	meta:
		description = "Virus de la policia"

	strings:
		$a = "ScheduleLockReceiver"
		$b = "AlarmManager"
		$c = "com.android.LockActivity"

	condition:
		all of them
}
