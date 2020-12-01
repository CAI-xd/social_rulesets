/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: joseangel
    Rule name: FakePostBank2
    Rule id: 2897
    Created at: 2017-05-31 20:01:39
    Updated at: 2017-05-31 20:02:34
    
    Rating: #0
    Total detections: 26
*/

/*
 * Regla para detectar la ocurrencia de nuestra muestra 
 */
rule FakePostBank {
meta:
descripton= "Regla para Detectar Fake Post Bank"
thread_level=3

strings:
	$a = "Lorg/slempo/service/Main;" wide ascii
	$b = "http://185.62.188.32/app/remote/" wide ascii
	$c = "&http://185.62.188.32/app/remote/forms/" wide ascii
	

condition:
	// The condition to match
	$a or $b or $c 
}
