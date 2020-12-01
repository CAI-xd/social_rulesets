/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_pkg_duniang
    Rule id: 4714
    Created at: 2018-07-31 02:47:33
    Updated at: 2018-07-31 02:54:20
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		url = " https://www.yangzhi968.com/20171112/du2.html?source=1"

	condition:
		androguard.package_name(/com.abel.abel/) or
		androguard.package_name(/com.ansun.IosFirstfang/) or
		androguard.package_name(/com.ansun.IosV2/) or
		androguard.package_name(/com.ansun.IosV2qp/) or
		androguard.package_name(/com.ansun.firstfang/) or
		androguard.package_name(/com.ansun.firstfangFr/) or
		androguard.package_name(/com.ansun.v2/) or
		androguard.package_name(/com.ansun.v2Fr/) or
		androguard.package_name(/com.app8412.IosIebbs/) or
		androguard.package_name(/com.app8412.LobbyGame/) or
		androguard.package_name(/com.app8412.SinBaGame/) or
		androguard.package_name(/com.app8412.iebbs/) or
		androguard.package_name(/com.app8412.iebbsFr/) or
		androguard.package_name(/com.bingo.IosBingo/) or
		androguard.package_name(/com.bingo.bingo/) or
		androguard.package_name(/com.bingo.bingoFr/) or
		androguard.package_name(/com.chester.NF0043/) or
		androguard.package_name(/com.chester.NF0043Fr/) or
		androguard.package_name(/com.chuxuan.chuxuan/) or
		androguard.package_name(/com.chuxuan.chuxuanFr/) or
		androguard.package_name(/com.duniang.IosDuniang/) or
		androguard.package_name(/com.duniang.IosDuniang2/) or
		androguard.package_name(/com.duniang.duniang/) or
		androguard.package_name(/com.duniang.duniangFr/) or
		androguard.package_name(/com.fd0371.AllFun/) or
		androguard.package_name(/com.fd0371.AllFun5Fr/) or
		androguard.package_name(/com.fd0371.AllFunFr/) or
		androguard.package_name(/com.fd0371.IceGame/) or
		androguard.package_name(/com.fd0371.IceGame9/) or
		androguard.package_name(/com.fd0371.IceGameFr/) or
		androguard.package_name(/com.fengniao.fengniao/) or
		androguard.package_name(/com.fengniao.fengniaoFr/) or
		androguard.package_name(/com.fuhao.IosFlbhqy/) or
		androguard.package_name(/com.fuhao.IosHqy/) or
		androguard.package_name(/com.fuhao.IosHqy3/) or
		androguard.package_name(/com.fuhao.flbhqy/) or
		androguard.package_name(/com.fuhao.flbhqyFr/) or
		androguard.package_name(/com.fuhao.hqy/) or
		androguard.package_name(/com.fuhao.hqyFr/) or
		androguard.package_name(/com.handui1026.LobbyGame/) or
		androguard.package_name(/com.haoyun.IosLucky/) or
		androguard.package_name(/com.haoyun.lucky/) or
		androguard.package_name(/com.haoyunqipai.haoyunqipai/) or
		androguard.package_name(/com.haoyunqipai.haoyunqipaiFr/) or
		androguard.package_name(/com.hch029.IosLobby/) or
		androguard.package_name(/com.hch029.LobbyDebug/) or
		androguard.package_name(/com.hch029.LobbyGame/) or
		androguard.package_name(/com.hch029.QLLobbyGame/) or
		androguard.package_name(/com.hiapps.HiappsBluePeak/) or
		androguard.package_name(/com.hiapps.HiappsDuniang/) or
		androguard.package_name(/com.hiapps.HiappsEagle/) or
		androguard.package_name(/com.hiapps.HiappsPaiquFr/) or
		androguard.package_name(/com.hiapps.HiappsTianyun/) or
		androguard.package_name(/com.hiapps.HiappsWinasking/) or
		androguard.package_name(/com.hiapps.HiappsYixiu/) or
		androguard.package_name(/com.hongyun.IosWinAsKing/) or
		androguard.package_name(/com.hongyun.WinAsKing/) or
		androguard.package_name(/com.hongyun.WinAsKingFr/) or
		androguard.package_name(/com.ianetest.dandanzhuan/) or
		androguard.package_name(/com.jinzun123.jinzun123/) or
		androguard.package_name(/com.jinzun123.jinzun123Fr/) or
		androguard.package_name(/com.jixiuqinga.jixiuqinga/) or
		androguard.package_name(/com.jixiuqinga.jixiuqingaFr/) or
		androguard.package_name(/com.jjqp.IosJiujiu/) or
		androguard.package_name(/com.jjqp.jiujiu/) or
		androguard.package_name(/com.jjqp.jiujiuFr/) or
		androguard.package_name(/com.juying.IosEagle/) or
		androguard.package_name(/com.juying.eagle/) or
		androguard.package_name(/com.juying.eagleFr/) or
		androguard.package_name(/com.jxqp.IosJixiang/) or
		androguard.package_name(/com.jxqp.jixiang/) or
		androguard.package_name(/com.jxqp.jixiangFr/) or
		androguard.package_name(/com.landing.IosBluePeak/) or
		androguard.package_name(/com.landing.blue_peak/) or
		androguard.package_name(/com.landing.blue_peak4/) or
		androguard.package_name(/com.landing.blue_peak40$/) or
		androguard.package_name(/com.landing.bluepeakFr/) or
		androguard.package_name(/com.leg1077.LobbyGame/) or
		androguard.package_name(/com.paiqu.IosPaiqu/) or
		androguard.package_name(/com.pearq12.LobbyGame/) or
		androguard.package_name(/com.qbqp.Ios7bao/) or
		androguard.package_name(/com.qbqp.Ios7baoFr/) or
		androguard.package_name(/com.qbqp.qibao/) or
		androguard.package_name(/com.qbqp.qibaoFr/) or
		androguard.package_name(/com.qbqp.qibao_001/) or
		androguard.package_name(/com.qyqp.IosQuying/) or
		androguard.package_name(/com.qyqp.quying/) or
		androguard.package_name(/com.qyqp.quyingFr/) or
		androguard.package_name(/com.sbxgame.IosLobbyGameFr/) or
		androguard.package_name(/com.sbxgame.LobbyDebug/) or
		androguard.package_name(/com.sbxgame.LobbyDemo/) or
		androguard.package_name(/com.sbxgame.LobbyGame/) or
		androguard.package_name(/com.sbxgame.LobbyGame0Fr/) or
		androguard.package_name(/com.sbxgame.LobbyGameFr/) or
		androguard.package_name(/com.soso.soso/) or
		androguard.package_name(/com.soso.sosoFr/) or
		androguard.package_name(/com.taizi.IosTz/) or
		androguard.package_name(/com.taizi.tz/) or
		androguard.package_name(/com.taizi.tzFr/) or
		androguard.package_name(/com.thai.TestSkin/) or
		androguard.package_name(/com.tianyun.IosHonor/) or
		androguard.package_name(/com.tianyun.IosHonor2/) or
		androguard.package_name(/com.tianyun.honor/) or
		androguard.package_name(/com.tianyun.liluo/) or
		androguard.package_name(/com.u9.IosPostive/) or
		androguard.package_name(/com.u9.positive02/) or
		androguard.package_name(/com.u9.postive/) or
		androguard.package_name(/com.u9.postiveFr/) or
		androguard.package_name(/com.unionasone.IosYixiu/) or
		androguard.package_name(/com.unionasone.yixiu/) or
		androguard.package_name(/com.unionasone.yixiuFr/) or
		androguard.package_name(/com.vip2002.vip2002/) or
		androguard.package_name(/com.vip2002.vip2002Fr/) or
		androguard.package_name(/com.wangzhe.cnty/) or
		androguard.package_name(/com.wangzhe.cntyFr/) or
		androguard.package_name(/com.wangzhe.thekingdom/) or
		androguard.package_name(/com.wangzhe.thekingdomFr/) or
		cuckoo.network.http_request(/\/route\/test/) or
		cuckoo.network.http_request(/\/service\/conf\/init?t=/)
		
}
