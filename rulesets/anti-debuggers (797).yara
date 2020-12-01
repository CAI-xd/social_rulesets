/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: Anti debuggers
    Rule id: 797
    Created at: 2015-08-25 19:36:15
    Updated at: 2015-08-28 16:54:03
    
    Rating: #3
    Total detections: 1320506
*/

rule AntiDebugger
{
	strings:
		$a = "/proc/%d/mem"
		$b = "/proc/%d/pagemap"
		$c = "inotify_init"
		$d = "strace"
		$e = "gdb"
		$f = "ltrace"
		$g = "android_server"
		$h = "dvmDbgActive"
		
	condition:
		($a or $b or $c) or ($d and $e and $f) or $g or $h
}
