/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: FlorisRick
    Rule name: Rule Batterysaver
    Rule id: 7182
    Created at: 2020-11-09 10:48:42
    Updated at: 2020-11-09 10:50:04
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule Batterysaver
{
    meta:
        Author = "F.S. Hessels"
        Email = "florishessels@gmail.com"
        Date = "08/11/2020"
        Description = "This is a basic YARA rule "
		Reference = "https://www.virustotal.com/gui/file/41fcb61c88f86092e6b302251cd6d6e12f26a8781f6df559859c2daa394ccecd/details"
        Sample = "f5abe3a486de57ce82dcc89e1a63376a"
    strings:
		$a = "http://ad.flurry.com/getAndroidApp.do"
        $b = "http://ad.flurry.com/getCanvas.do"
        $c = "http://d371dlrbpeyd2.cloudfront.net/upgrade/"
        $d = "http://data.flurry.com/aap.do"
        $e = "http://github.com/droidfu/schema"
        $f = "http://lp.mobsqueeze.com/"
        $g = "http://moba.rsigma.com/Localytics/Upload/%s"
        $h = "http://sigma.sgadtracker.com/Event/Put/"
        $i = "http://www.androiddoctor.com/help"
        $j = "https://bugsense.appspot.com/api/errors"
        $k = "https://chart.googleapis.com/chart?cht=p3&chs=250x300&chd=t:"
        $l = "https://data.flurry.com/aap.do"
        $m = "https://market.android.com/details?id="
        $n = "https://ws.tapjoyads.com/"
        $o = "https://ws.tapjoyads.com/connect?"
        $p = "https://ws.tapjoyads.com/offer_completed?"
        $q = "https://ws.tapjoyads.com/set_publisher_user_id?"
        $r = "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=8246419"

    condition:
        all of them
}
