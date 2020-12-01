/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: gentlevandal
    Rule name: Test Rule Legu Packer
    Rule id: 6233
    Created at: 2019-12-19 20:51:56
    Updated at: 2019-12-19 23:44:11
    
    Rating: #1
    Total detections: 160
*/

rule legu : packer
{
    meta:
		description = "test rule to identify Legu Packer"
	strings:
		$a = "assets/toversion"
		$b = "assets/0OO00l111l1l"
		$c = "assets/0OO00oo01l1l"
		$d = "assets/o0oooOO0ooOo.dat"
	condition:
	    // previous: all of them
		$b and ($a or $c or $d)

}
