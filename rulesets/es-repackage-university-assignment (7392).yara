/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Gijs
    Rule name: ES repackage (university assignment)
    Rule id: 7392
    Created at: 2020-11-18 08:25:44
    Updated at: 2020-11-18 11:11:36
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule repackage : ESFileExplorer
{
	meta:
		description = "This is a YARA made as an exercise for a security course at the university of Leiden, checking hashes of dropped files found with TotalVirus"
		source = "https://koodous.com/apks/8d2af30355950ad6fbe0bddb94d08146e4a29ec6649996aa6146fc70c5208ab4"

	strings:
		$a = "e6e946529bc1171f6c62168f9e9943613261062373f5c89330e15d9778c5355b"
		$b = "06fd44e4a8268c4b69f873be0daa00de36214b8521673f059700fae638028cda"
		$c = "33cc60e3851c2d813b95b6e2a6405a7e31d76be95de3a1050f03f44c5ee23c09"
		$d = "a7fef32d5e603306b064b2f9d8bb197fc13d9e798ebaa3862e703e479462485a"
		$e = "/data/data/com.estrongs.android.pop/code_cache/secondary-dexes/com.estrongs.android.pop-1.apk.classes2.zip" 
		$f = "/data/data/com.estrongs.android.pop/code_cache/secondary-dexes/com.estrongs.android.pop-1.apk.classes3.zip"

	condition:
		( $a and $b and $c and $d ) or ( $e and $f )
		
}
