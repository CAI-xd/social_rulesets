/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Android_Catelite_Bot
    Rule id: 3922
    Created at: 2017-12-26 15:55:31
    Updated at: 2018-02-15 09:20:03
    
    Rating: #-1
    Total detections: 85
*/

import "androguard"
import "droidbox"


rule catelites
{

               strings:
                              $db1 = "Successfully updated \"%1$s\""
                              $db2 = "Added %1$s to %2$s balance."
                              $db3 = "Touch to sign in to your account."
                              $db4 = "You will be automatically charged %1$s"

               condition:
                              all of them
                              or
                              (
                                            droidbox.written.filename(/V3a3i1iqN.xml/) and
                                            droidbox.written.data(/http/)
                              )
                              
}
