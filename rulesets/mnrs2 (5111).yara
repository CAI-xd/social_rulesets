/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: zyrik
    Rule name: mnrs2
    Rule id: 5111
    Created at: 2018-12-05 18:59:22
    Updated at: 2019-03-08 16:55:57
    
    Rating: #1
    Total detections: 3782
*/

import "androguard"
import "file"
import "cuckoo"


rule potential_miners_by_strings : miner 
{
	meta:
		description = "This rule detects potential miners using set of strings"
		author = "https://koodous.com/analysts/zyrik"

	strings:
        $id001 = "4Cf2TfMKhCgJ2vsM3HeBUnYe52tXrvv8X1ajjuQEMUQ8iU8kvUzCSsCEacxFhEmeb2JgPpQ5chdyw3UiTfUgapJBhBKu2R58FcyCP2RKyq"
        $id002 = "44V8ww9soyFfrivJDfcgmT2gXCFPQDyLFXyS7mEo2xTSaf7NFXAL9usGxrko3aKauBGcwZaF1duCWc2p9eDNt9H7Q8iB7gy"
        $id003 = "43QGgipcHvNLBX3nunZLwVQpF6VbobmGcQKzXzQ5xMfJgzfRBzfXcJHX1tUHcKPm9bcjubrzKqTm69JbQSL4B3f6E3mNCbU"
        $id004 = "45vSqhWgnyRKKjmiUsSpnd14UZpMoVgZWARvyepZY1fEdERMnG6gyzB8ziGB5fCg9cfoKywXdgvXVg1E9bxzPbc8CSE5huQ"
        $id005 = "46yzCCD3Mza9tRj7aqPSaxVbbePtuAeKzf8Ky2eRtcXGcEgCg1iTBio6N4sPmznfgGEUGDoBz5CLxZ2XPTyZu1yoCAG7zt6"
        $id006 = "422QQNhnhX8hmMEkF3TWePWSvKm6DiV7sS3Za2dXrynsJ1w8U6AzwjEdnewdhmP3CDaqvaS6BjEjGMK9mnumtufvLmz5HJi"
        $id007 = "42DEobaAFK67GTxX359z83ecfa2imuqgRdrdhDRo4qGnXU6WijcjmHfQoucNPxQaZjgkkG5DWkahi8QnsXKgapfhRHo4xud"
        $id008 = "43FeFPuaspxAEU7ZGEY93YBmG8nkA1x1Pgg5kTh7mYuLXCzMP3hERey6QBdKKBciuqhsakJD44bGHhJX98V3VjbZ9r1LKzx"
        $id009 = "45oLJdzMCfPFrtz46yqNNyTNKPFRvye5XB94R7sDWvZQZmoyPy6pfk9fdgJaXFs5Jp7F8R8V42UoxjXKE2Ze842Q18Lx24G"
        $id010 = "44yphkVFNewhMGi8LkgfYSSo4gbpnT7uPeGdtwvACMB6S4zY2B6D3iWY9yF7mFX6rbJ3A3fCd8cqJVbW2zYEJLLGEnYfhLy"
        $id011 = "49Bq2bFsvJFAe11SgAZQZjZRn6rE2CXHz4tkoomgx4pZhkJVSUmUHT4ixRWdGX8z2cgJeftiyTEK1U1DW7mEZS8E4dF5hkn"
        $id012 = "4ASDBruxfJ4in134jDC1ysNPjXase7sQwZZfnLCdyVggfsaJB1AxSA8jVnXwLEe1vjBhG7sfpssqMZ8YCSAkuFCELvhUaQ1"
        $id013 = "Q0105005d36e565f5487c1d950e59a04c05c4f410345d460d8bd4d59ca2428fe7b69cf6b787fa92"
        $id014 = "44ea2ae6ec816e7955d27bf6af2f7c2e6ce36c142ee34e428dbcc808af9bc078"
        $id015 = "515b125d8a9fbc944f8652841869335d21fb0a2968c3"
        $id016 = "RHDMXKDoD2aYDwX5PRM0IUfNrQMv9yCR"
        $id017 = "1eUqLvDauJzZUjLlxvEBJfaMXpcCvOum"
        $id018 = "OkcKKX6waOTc0sRFwJXdh5PFTobpRMow"
        $id019 = "6GlWvU4BbBgzJ3wzL3mkJEVazCxxIHjF"
        $id020 = "8LqXh2UY7QzxwK2PrIQLn3iwd7HfuYgt"
        $id021 = "BLAXcU2ALlc06bhhl4Dj64Wbj44hnKYO"
        $id022 = "bLXRob0Mov5Po9c0fSrXexaJkciBo5Dp"
        $id023 = "E2B9t9yVqR62YaRw4wWX3jfadGdxcRfH"
        $id024 = "esp9hnZ3rOao2IadnClF11r6PWtExGAB"
        $id025 = "f4JsDABslmUsqfqa1SqBxbdUFp9h8eAe"
        $id026 = "InSicsHzpAQpeRBTvV2bCRT3J5mK8IoH"
        $id027 = "ITERXYJEQszTERbPanh7CxXanvT64Q5C"
        $id028 = "N09gjytzJzCQzFy9MRuchpT6TzqMXjVB"
        $id029 = "nS4VZBZRmBGNvzfQN57Mu4aodai7Hh9U"
        $id030 = "o2nnEz8ECFPcZvqSInL1Z1xcbyYvpqzD"
        $id031 = "pRdnpY8EOPrnZdDDqYStGOTLNborIkCY"
        $id032 = "tx82bQv1RTVR5V0fe2hUMSkmyNw9zmlS"
        $id033 = "v2RuDMli7TYzHF7ge0lG5VLYUDp5ISM3"
        $id034 = "W9e1JbsYTHqCwImFfAEGfJJigBCWfYv2"
        $id035 = "Xo54zUaiQUexHS1nEkT6b038trLnt0vg"
        $id036 = "XxTxffZJjxU8rLviOim34l5O3MJMWmDK"
        $id037 = "uBiTW6jSZk7mqG4mJRq4TeHMYhwu96it"
        $id038 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id039 = "ZjWTajjTeo0IFi1lE3ArPpJ9MCnsimm7"
        $id040 = "pfSLncN8wTEksroVnGo5qE2rlc0zPsu4"
        $id041 = "p3ghDUhs89AhpWiQqh01aBbSFO9BQfR6"
        $id042 = "qqWrKdZTVrXznFYcZ1icdXh3mjROzyhQ"
        $id043 = "ejYytKXlz2qRKYxsHp7yeqPyEF93sMOx"
        $id044 = "VOTOnyFz4gLoYQokkyZ0O2C67UgejX14"
        $id045 = "HtQkBqXwvzRHUdngvFWg1j84fQ62RnVo"
        $id046 = "cJsrc2H0m8rKjzXo4CF7cPLcg6znPogR"
        $id047 = "lRzS5W2NgHybxcbH5BHNnNat4QajQy51"
        $id048 = "9eJhVNC0dT3qgLWnnz0ojYkBJWDZONpO"
        $id049 = "JTGErE8qg0xjlgI8aJckAqX7uamxBCyb"
        $id050 = "ciIJoDEHvWDsFjUHfX7nDMuADREcBMjD"
        $id051 = "ivFo3gzNufGSFc4lAS7dbQecVnEwf2fn"
        $id052 = "nUNBYr6kljQAEVkfLgxRY2UavY6okT4y"
        $id053 = "rD0u5dQUdYEhyHzdUt4b4HFj5OnQfylx"
        $id054 = "sdibwtwKsYZue7Q7yCoKPy7ZwIeweQXw"
        $id055 = "CxHsGJiU1DItubcIa6r7T8bK27a4eUZG"
        $id056 = "NPYVnbZeXgvboqWU0pzUVasryJgShjMU"
        $id057 = "6VLUnZXGvLqDuABUvERNwKObgOPDnB2j"
        $id058 = "YQ1at78RnEjeEiIRzLGAGY9lFo4iHU8v"
        $id059 = "4O99dpG3I4wBLhRLutkoA2cIAkWxqiZl"
        $id060 = "DulPovFs1oAWloQEruJIMlBpsDooMI1f"
        $id061 = "nYt8fRXPWp92u8MHvtdNVOoyuYdfZIdd"
        $id062 = "fwW95bBFO91OKUsz1VhlMEQwxmDBz7XE"
        $id063 = "8SUFoIbdMUfwgDVAXgyyaC5R1k1B2ny1"
        $id064 = "1a0Cej64dYffEiItrLIeiq4GfpPtn0Hf"
        $id065 = "pnkGf8QJ92Z7QEhw8exumIL8HjKCBveQ"
        $id066 = "EjGZOcQjjaAU6sPmgtoUtgfxJSzAI7Id"
        $id067 = "3ARWsJFCmo3Kg13cnr4BAW3fP5uLLoMsbL"
        $id068 = "jPypuxLViIH1ZNallVeg9LqypsYK0wq9"
        $id069 = "ugrZV7MvW9J6Wfa1NgE7qwXFmTHhYorj"
        $id070 = "aX3rvYs5vmuTbT0rr83UDiUD0VolYCkZ"
        $id071 = "1DLnwEX2GUhmRA62aCMAveHPzUN9m2dd"
        $id072 = "8P3iejGFCkXynNojWYArCRBZ21J6zrDy"
        $id073 = "y7cM7qd7ZEEQ6MdkCtDdwo6EcOpe6Oyu"
        $id074 = "dsQIV8MsvvWHB1Q8Ky1faRlpU0qzYVg1"
        $id075 = "fljRO8IOscGvuIX6I2N6agxzVM9XoYXt"
        $id076 = "1a0Cej64dYffEiItrLIeiq4GfpPtn0Hf"
        $id077 = "dzZiMNu2ju00u997BHk2uk6n6GKbtuXw"
        $id078 = "OE4oIwyeXe5YImXY5lDLscoZZrhm9DDN"
        $id079 = "eKoOYNLHEMxcmFXrQnARORLeZo9SMlZR"
        $id080 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id081 = "HN0DRyXrOpCbdkyWIZnC7UjMeXvFtkh0"
        $id082 = "1nK3FmVEeZ0bjc6Np1r63wkynuTP3oqU"
        $id083 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id084 = "c0aYHt9KgnXUpmZkm7tGPW2rGXl2bM2d"
        $id085 = "bXjy6ex2L7E4nI7RATUXKQKlRVeY8pyw"
        $id086 = "ZPKnEehMXNylSyz6HFP7xBUlCADEIcPy"
        $id087 = "fqJfdzGDvfwbedsKSUGty3VZ9taXxMVw"
        $id088 = "PT13WGgxMmJoaEdMc3dDTDE5Mlp2TjNY"
        $id089 = "Jz0IWB14EmMzZDdMc3dDdnZ4R2tsaDI9"
        $id090 = "PEDk4i0UIq7GsUEAEwXs31dqKjDHUI3z"
        $id091 = "FYEAbFBG3xY5VUtE9GXC56v5UKt4xkoUkb"
        $id092 = "2HujvzmUo2nuRLLqhIHIV4sCEmRw9FIc"
        $id093 = "5xUKpsv5UFOcqf6dToqMDAtBYKn1WavS"
        $id094 = "9AYxnHCZ2H7MwagCSMDwLiSizaSbqhSp"
        $id095 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        $id096 = "anWcowZ0OspSk7SPFH0itFrDrNyCpVXp"
        $id097 = "cLfiFmhE82tUfGodiYgS3U1ewQpMa2nc"
        $id098 = "DUMWz54MXfCcQGUufjx7aeBlGgaurUcU"
        $id099 = "dWzYVbhggge684eSOBSvN7gEoGs9Mjc"
        $id100 = "fz0unvRkvThZ7DcPzxfMnZoTEpZJoblt"
        $id101 = "JCchrP65tMKei1yeLQGtaOdZxXtxZryy"
        $id103 = "o2iHliDUYieOuXz3wME2NjZW79a5apK5"
        $id104 = "oQtjTDL7Jzpj8yTCD8RJMN3cxLt3pXUD"
        $id105 = "QnXbx7vLFIUq9FT0kfNZSjBkUD0GCcqi"
        $id106 = "ZHg7IgsgCYIQLhWEnLVFq06yKedNkKC9"
        $id107 = "eXnvyAQwXxGV80C4fGuiRiDZiDpDaSrf"
        $id108 = "1NeoArmnGyWHKfbje9JNWqw3tquMY7jHCw"
        $id109 = "LA7Ida655adggnBNrMgKfj7ufCwUSBQwZb7"
        $id110 = "BX9yNHd8IZ9oBVGp3ciPBdysVkmAGWv7"
        $id111 = "Vi0mvlm3aS8xDeOTMyD4vvlyPG95dbDZ"
        $id112 = "gidVWyszRjxYBNC1IoxeIDTqSK17ZAT5"
        $id113 = "SmOkuf8IXMjW1WCUeOY2EWPcjt7Ina96"
        $id114 = "lFoT0JKyWO4wh2BX7f5G4Ilg09mlnfoz"


        $link000 = "my.electroneum.com"
        $link001 = "api.electroneum.com"
        $link002 = "api.coinhive.com"
        $link003 = "ftp.coinhive-manager.com"
        $link004 = "coinhive.com"
        $link005 = "coinhiver.com"
        $link006 = "coinhives.com"
        $link007 = "coinhiveproxy.com"
        $link008 = "coinhive-proxy.party"
        $link009 = "coinhive-manager.com"
        $link010 = "coinhive.info"
        $link011 = "coinhive.net"
        $link012 = "coinhive.org"
        $link013 = "apin.monerise.com"
        $link014 = "authedmine.eu"
        $link015 = "authedmine.com"
        $link016 = "50million.club"
        $link017 = "primary.coinhuntr.com"
        $link018 = "api.bitcoin.cz"
        $link019 = "cryptominingfarm.io"
        $link020 = "litecoinpool.org"
        $link021 = "us.litecoinpool.org"
        $link022 = "us2.litecoinpool.org"
        $link023 = "www.rexminer.com/mobil"
        $link024 = "www.megaproxylist.net/appmonerominer/minerxmr.aspx"
        $link025 = "pool.supportxmr.com"
        $link026 = "poolw.etnpooler.com"
        $link027 = "xmr.nanopool.org"
        $link028 = "nyc01.supportxmr.com"
        $link029 = "hk01.supportxmr.com"
        $link030 = "hk02.supportxmr.com"
        $link031 = "fr04.supportxmr.com"
        $link032 = "qrl.herominers.com"
        $link033 = "akgpr.com/Mining"
        $link034 = "www.buyguard.co/sdk/"
        $link035 = "mrpool.net"
        $link036 = "raw.githubusercontent.com/cryptominesetting"
        $link037 = "miner.mobeleader.com/miner.php"
        $link038 = "github.com/C0nw0nk/CoinHive"
        $link039 = "stratum+tcp://litecoinpool.org"
        $link040 = "stratum+tcp://eu.multipool.us"
        $link041 = "stratum+tcp://stratum.bitcoin.cz"
        $link042 = "stratum+tcp://groestlcoin.biz"
        $link043 = "com.puregoldapps.eth.mine"
        $link044 = "api.kanke365.com"
        $link045 = "cnhv.co"
        $link046 = "coin-hive.com"
        $link047 = "coinhive.com"
        $link048 = "authedmine.com"
        $link049 = "api.jsecoin.com"
        $link050 = "load.jsecoin.com"
        $link051 = "server.jsecoin.com"
        $link052 = "miner.pr0gramm.com"
        $link053 = "minemytraffic.com"
        $link054 = "ppoi.org"
        $link055 = "projectpoi.com"
        $link056 = "crypto-loot.com"
        $link057 = "cryptaloot.pro"
        $link058 = "cryptoloot.pro"
        $link059 = "coinerra.com"
        $link060 = "coin-have.com"
        $link061 = "minero.pw"
        $link062 = "minero-proxy-01.now.sh"
        $link063 = "minero-proxy-02.now.sh"
        $link064 = "minero-proxy-03.now.sh"
        $link065 = "api.inwemo.com"
        $link066 = "rocks.io"
        $link067 = "adminer.com"
        $link068 = "ad-miner.com"
        $link069 = "jsccnn.com"
        $link070 = "jscdndel.com"
        $link071 = "coinhiveproxy.com"
        $link072 = "coinblind.com"
        $link073 = "coinnebula.com"
        $link074 = "monerominer.rocks"
        $link075 = "cdn.cloudcoins.co"
        $link076 = "coinlab.biz"
        $link077 = "go.megabanners.cf"
        $link078 = "baiduccdn1.com"
        $link079 = "wsp.marketgid.com"
        $link080 = "papoto.com"
        $link081 = "flare-analytics.com"
        $link082 = "www.sparechange.io"
        $link083 = "static.sparechange.io"
        $link084 = "miner.nablabee.com"
        $link085 = "m.anyfiles.ovh"
        $link086 = "coinimp.com"
        $link087 = "coinimp.net"
        $link088 = "freecontent.bid"
        $link089 = "freecontent.date"
        $link090 = "freecontent.faith"
        $link091 = "freecontent.loan"
        $link092 = "freecontent.racing"
        $link093 = "freecontent.win"
        $link094 = "blockchained.party"
        $link095 = "hostingcloud.download"
        $link096 = "cryptonoter.com"
        $link097 = "mutuza.win"
        $link098 = "crypto-webminer.com"
        $link099 = "cdn.adless.io"
        $link100 = "hegrinhar.com"
        $link101 = "verresof.com"
        $link102 = "hemnes.win"
        $link103 = "tidafors.xyz"
        $link104 = "moneone.ga"
        $link105 = "plexcoin.info"
        $link106 = "www.monkeyminer.net"
        $link107 = "go2.mercy.ga"
        $link108 = "coinpirate.cf"
        $link109 = "d.cpufan.club"
        $link110 = "krb.devphp.org.ua"
        $link111 = "nfwebminer.com"
        $link112 = "cfcdist.gdn"
        $link113 = "node.cfcdist.gdn"
        $link114 = "webxmr.com"
        $link115 = "xmr.mining.best"
        $link116 = "webminepool.com"
        $link117 = "webminepool.tk"
        $link118 = "hive.tubetitties.com"
        $link119 = "playerassets.info"
        $link120 = "tokyodrift.ga"
        $link121 = "webassembly.stream"
        $link122 = "www.webassembly.stream"
        $link123 = "okeyletsgo.ml"
        $link124 = "candid.zone"
        $link125 = "webmine.pro"
        $link126 = "andlache.com"
        $link127 = "bablace.com"
        $link128 = "bewaslac.com"
        $link129 = "biberukalap.com"
        $link130 = "bowithow.com"
        $link131 = "butcalve.com"
        $link132 = "evengparme.com"
        $link133 = "gridiogrid.com"
        $link134 = "hatcalter.com"
        $link135 = "kedtise.com"
        $link136 = "ledinund.com"
        $link137 = "nathetsof.com"
        $link138 = "renhertfo.com"
        $link139 = "rintindown.com"
        $link140 = "sparnove.com"
        $link141 = "witthethim.com"
        $link142 = "1q2w3.fun"
        $link143 = "1q2w3.me"
        $link144 = "bjorksta.men"
        $link145 = "crypto.csgocpu.com"
        $link146 = "noblock.pro"
        $link147 = "miner.cryptobara.com"
        $link148 = "digger.cryptobara.com"
        $link149 = "dev.cryptobara.com"
        $link150 = "reservedoffers.club"
        $link151 = "mine.torrent.pw"
        $link152 = "host.d-ns.ga"
        $link153 = "abc.pema.cl"
        $link154 = "js.nahnoji.cz"
        $link155 = "mine.nahnoji.cz"
        $link156 = "webmine.cz"
        $link157 = "www.webmine.cz"
        $link158 = "intactoffers.club"
        $link159 = "analytics.blue"
        $link160 = "smectapop12.pl"
        $link161 = "berserkpl.net.pl"
        $link162 = "hodlers.party"
        $link163 = "hodling.faith"
        $link164 = "chainblock.science"
        $link165 = "minescripts.info"
        $link166 = "cdn.minescripts.info"
        $link167 = "miner.nablabee.com"
        $link168 = "wss.nablabee.com"
        $link169 = "clickwith.bid"
        $link170 = "dronml.ml"
        $link171 = "niematego.tk"
        $link172 = "tulip18.com"
        $link173 = "p.estream.to"
        $link174 = "didnkinrab.com"
        $link175 = "ledhenone.com"
        $link176 = "losital.ru"
        $link177 = "mebablo.com"
        $link178 = "moonsade.com"
        $link179 = "nebabrop.com"
        $link180 = "pearno.com"
        $link181 = "rintinwa.com"
        $link182 = "willacrit.com"
        $link183 = "www2.adfreetv.ch"
        $link184 = "minr.pw"
        $link185 = "new.minr.pw"
        $link186 = "test.minr.pw"
        $link187 = "staticsfs.host"
        $link188 = "cdn-code.host"
        $link189 = "g-content.bid"
        $link190 = "ad.g-content.bid"
        $link191 = "cdn.static-cnt.bid"
        $link192 = "cnt.statistic.date"
        $link193 = "jquery-uim.download"
        $link194 = "cdn.jquery-uim.download"
        $link195 = "cdn-jquery.host"
        $link196 = "p1.interestingz.pw"
        $link197 = "kippbeak.cf"
        $link198 = "pasoherb.gq"
        $link199 = "axoncoho.tk"
        $link200 = "depttake.ga"
        $link201 = "flophous.cf"
        $link202 = "pr0gram.org"
        $link203 = "authedmine.eu"
        $link204 = "www.monero-miner.com"
        $link205 = "www.datasecu.download"
        $link206 = "www.jquery-cdn.download"
        $link207 = "www.etzbnfuigipwvs.ru"
        $link208 = "www.terethat.ru"
        $link209 = "freshrefresher.com"
        $link210 = "api.pzoifaum.info"
        $link211 = "ws.pzoifaum.info"
        $link212 = "api.bhzejltg.info"
        $link213 = "ws.bhzejltg.info"
        $link214 = "d.cfcnet.top"
        $link215 = "vip.cfcnet.top"
        $link216 = "eu.cfcnet.top"
        $link217 = "as.cfcnet.top"
        $link218 = "us.cfcnet.top"
        $link219 = "eu.cfcdist.loan"
        $link220 = "as.cfcdist.loan"
        $link221 = "us.cfcdist.loan"
        $link222 = "gustaver.ddns.net"
        $link223 = "worker.salon.com"
        $link224 = "s2.appelamule.com"
        $link225 = "mepirtedic.com"
        $link226 = "cdn.streambeam.io"
        $link227 = "adzjzewsma.cf"
        $link228 = "ffinwwfpqi.gq"
        $link229 = "ininmacerad.pro"
        $link230 = "mhiobjnirs.gq"
        $link231 = "open-hive-server-1.pp.ua"
        $link232 = "pool.hws.ru"
        $link233 = "pool.etn.spacepools.org"
        $link234 = "api.aalbbh84.info"
        $link235 = "www.aymcsx.ru"
        $link236 = "aeros01.tk"
        $link237 = "aeros02.tk"
        $link238 = "aeros03.tk"
        $link239 = "aeros04.tk"
        $link240 = "aeros05.tk"
        $link241 = "aeros06.tk"
        $link242 = "aeros07.tk"
        $link243 = "aeros08.tk"
        $link244 = "aeros09.tk"
        $link245 = "aeros10.tk"
        $link246 = "aeros11.tk"
        $link247 = "aeros12.tk"
        $link248 = "npcdn1.now.sh"
        $link249 = "mxcdn2.now.sh"
        $link250 = "sxcdn6.now.sh"
        $link251 = "mxcdn1.now.sh"
        $link252 = "sxcdn02.now.sh"
        $link253 = "sxcdn4.now.sh"
        $link254 = "jqcdn2.herokuapp.com"
        $link255 = "sxcdn1.herokuapp.com"
        $link256 = "sxcdn5.herokuapp.com"
        $link257 = "wpcdn1.herokuapp.com"
        $link258 = "jqcdn01.herokuapp.com"
        $link259 = "jqcdn03.herokuapp.com"
        $link260 = "1q2w3.website"
        $link261 = "video.videos.vidto.me"
        $link262 = "play.play1.videos.vidto.me"
        $link263 = "playe.vidto.se"
        $link264 = "video.streaming.estream.to"
        $link265 = "eth-pocket.de"
        $link266 = "xvideosharing.site"
        $link267 = "bestcoinsignals.com"
        $link268 = "eucsoft.com"
        $link269 = "traviilo.com"
        $link270 = "wasm24.ru"
        $link271 = "xmr.cool"
        $link272 = "api.netflare.info"
        $link273 = "cdnjs.cloudflane.com"
        $link274 = "www.cloudflane.com"
        $link275 = "clgserv.pro"
        $link276 = "hide.ovh"
        $link277 = "graftpool.ovh"
        $link278 = "encoding.ovh"
        $link279 = "altavista.ovh"
        $link280 = "scaleway.ovh"
        $link281 = "nexttime.ovh"
        $link282 = "never.ovh"
        $link283 = "2giga.download"
        $link284 = "support.2giga.link"
        $link285 = "webminerpool.com"
        $link286 = "minercry.pt"
        $link287 = "adplusplus.fr"
        $link288 = "ethtrader.de"
        $link289 = "gobba.myeffect.net"
        $link290 = "bauersagtnein.myeffect.net"
        $link291 = "besti.ga"
        $link292 = "jurty.ml"
        $link293 = "jurtym.cf"
        $link294 = "mfio.cf"
        $link295 = "mwor.gq"
        $link296 = "oei1.gq"
        $link297 = "wordc.ga"
        $link298 = "berateveng.ru"
        $link299 = "ctlrnwbv.ru"
        $link300 = "ermaseuc.ru"
        $link301 = "kdmkauchahynhrs.ru"
        $link302 = "uoldid.ru"
        $link303 = "jqrcdn.download"
        $link304 = "jqassets.download"
        $link305 = "jqcdn.download"
        $link306 = "jquerrycdn.download"
        $link307 = "jqwww.download"
        $link308 = "lightminer.co"
        $link309 = "www.lightminer.co"
        $link310 = "browsermine.com"
        $link311 = "api.browsermine.com"
        $link312 = "mlib.browsermine.com"
        $link313 = "bmst.pw"
        $link314 = "bmnr.pw"
        $link315 = "bmcm.pw"
        $link316 = "bmcm.ml"
        $link317 = "videoplayer2.xyz"
        $link318 = "play.video2.stream.vidzi.tv"
        $link319 = "001.0x1f4b0.com"
        $link320 = "002.0x1f4b0.com"
        $link321 = "003.0x1f4b0.com"
        $link322 = "004.0x1f4b0.com"
        $link323 = "005.0x1f4b0.com"
        $link324 = "006.0x1f4b0.com"
        $link325 = "007.0x1f4b0.com"
        $link326 = "008.0x1f4b0.com"
        $link327 = "authedwebmine.cz"
        $link328 = "www.authedwebmine.cz"
        $link329 = "skencituer.com"
        $link330 = "site.flashx.cc"
        $link331 = "play1.flashx.pw"
        $link332 = "play2.flashx.pw"
        $link333 = "play4.flashx.pw"
        $link334 = "play5.flashx.pw"
        $link335 = "js.vidoza.net"
        $link336 = "mm.zubovskaya-banya.ru"
        $link337 = "mysite.irkdsu.ru"
        $link338 = "play.estream.nu"
        $link339 = "play.estream.to"
        $link340 = "play.estream.xyz"
        $link341 = "play.play.estream.nu"
        $link342 = "play.play.estream.to"
        $link343 = "play.play.estream.xyz"
        $link344 = "play.tainiesonline.pw"
        $link345 = "play.vidzi.tv"
        $link346 = "play.pampopholf.com"
        $link347 = "s3.pampopholf.com"
        $link348 = "play.malictuiar.com"
        $link349 = "s3.malictuiar.com"
        $link350 = "play.play.tainiesonline.stream"
        $link351 = "ocean2.authcaptcha.com"
        $link352 = "rock2.authcaptcha.com"
        $link353 = "stone2.authcaptcha.com"
        $link354 = "sass2.authcaptcha.com"
        $link355 = "sea2.authcaptcha.com"
        $link356 = "play.flowplayer.space"
        $link357 = "play.pc.belicimo.pw"
        $link358 = "play.power.tainiesonline.pw"
        $link359 = "play.s01.vidtodo.pro"
        $link360 = "play.cc.gofile.io"
        $link361 = "wm.yololike.space"
        $link362 = "play.mix.kinostuff.com"
        $link363 = "play.on.animeteatr.ru"
        $link364 = "play.mine.gay-hotvideo.net"
        $link365 = "play.www.intellecthosting.net"
        $link366 = "mytestminer.xyz"
        $link367 = "play.vb.wearesaudis.net"
        $link368 = "flowplayer.space"
        $link369 = "s2.flowplayer.space"
        $link370 = "s3.flowplayer.space"
        $link371 = "thersprens.com"
        $link372 = "s2.thersprens.com"
        $link373 = "s3.thersprens.com"
        $link374 = "play.gramombird.com"
        $link375 = "ugmfvqsu.ru"
        $link376 = "bsyauqwerd.party"
        $link377 = "ccvwtdtwyu.trade"
        $link378 = "baywttgdhe.download"
        $link379 = "pdheuryopd.loan"
        $link380 = "iaheyftbsn.review"
        $link381 = "djfhwosjck.bid"
        $link382 = "najsiejfnc.win"
        $link383 = "zndaowjdnf.stream"
        $link384 = "yqaywudifu.date"
        $link385 = "malictuiar.com"
        $link386 = "proofly.win"
        $link387 = "zminer.zaloapp.com"
        $link388 = "vkcdnservice.com"
        $link389 = "dexim.space"
        $link390 = "acbp0020171456.page.tl"
        $link391 = "vuryua.ru"
        $link392 = "minexmr.stream"
        $link393 = "gitgrub.pro"
        $link394 = "d8acddffe978b5dfcae6.date"
        $link395 = "eth-pocket.com"
        $link396 = "autologica.ga"
        $link397 = "whysoserius.club"
        $link398 = "aster18cdn.nl"
        $link399 = "nerohut.com"
        $link400 = "gnrdomimplementation.com"
        $link401 = "pon.ewtuyytdf45.com"
        $link402 = "hhb123.tk"
        $link403 = "dzizsih.ru"
        $link404 = "nddmcconmqsy.ru"
        $link405 = "silimbompom.com"
        $link406 = "unrummaged.com"
        $link407 = "fruitice.realnetwrk.com"
        $link408 = "synconnector.com"
        $link409 = "toftofcal.com"
        $link410 = "gasolina.ml"
        $link411 = "8jd2lfsq.me"
        $link412 = "afflow.18-plus.net"
        $link413 = "afminer.com"
        $link414 = "aservices.party"
        $link415 = "becanium.com"
        $link416 = "brominer.com"
        $link417 = "cdn-analytics.pl"
        $link418 = "cdn.static-cnt.bid"
        $link419 = "cloudcdn.gdn"
        $link420 = "coin-service.com"
        $link421 = "coinpot.co"
        $link422 = "coinrail.io"
        $link423 = "etacontent.com"
        $link424 = "exdynsrv.com"
        $link425 = "formulawire.com"
        $link426 = "go.bestmobiworld.com"
        $link427 = "goldoffer.online"
        $link428 = "hallaert.online"
        $link429 = "hashing.win"
        $link430 = "igrid.org"
        $link431 = "laserveradedomaina.com"
        $link432 = "machieved.com"
        $link433 = "nametraff.com"
        $link434 = "offerreality.com"
        $link435 = "ogrid.org"
        $link436 = "panelsave.com"
        $link437 = "party-vqgdyvoycc.now.sh"
        $link438 = "pertholin.com"
        $link439 = "premiumstats.xyz"
        $link440 = "serie-vostfr.com"
        $link441 = "salamaleyum.com"
        $link442 = "smartoffer.site"
        $link443 = "stonecalcom.com"
        $link444 = "thewhizmarketing.com"
        $link445 = "thewhizproducts.com"
        $link446 = "thewise.com"
        $link447 = "traffic.tc-clicks.com"
        $link448 = "vcfs6ip5h6.bid"
        $link449 = "web.dle-news.pw"
        $link450 = "webmining.co"
        $link451 = "wp-monero-miner.de"
        $link452 = "wtm.monitoringservice.co"
        $link453 = "xy.nullrefexcep.com"
        $link454 = "yrdrtzmsmt.com"
        $link455 = "wss.rand.com.ru"
        $link456 = "verifier.live"
        $link457 = "jshosting.bid"
        $link458 = "jshosting.date"
        $link459 = "jshosting.download"
        $link460 = "jshosting.faith"
        $link461 = "jshosting.loan"
        $link462 = "jshosting.party"
        $link463 = "jshosting.racing"
        $link464 = "jshosting.review"
        $link465 = "jshosting.science"
        $link466 = "jshosting.stream"
        $link467 = "jshosting.trade"
        $link468 = "jshosting.win"
        $link469 = "freecontent.download"
        $link470 = "freecontent.party"
        $link471 = "freecontent.review"
        $link472 = "freecontent.science"
        $link473 = "freecontent.stream"
        $link474 = "freecontent.trade"
        $link475 = "hostingcloud.bid"
        $link476 = "hostingcloud.date"
        $link477 = "hostingcloud.faith"
        $link478 = "hostingcloud.loan"
        $link479 = "hostingcloud.party"
        $link480 = "hostingcloud.racing"
        $link481 = "hostingcloud.review"
        $link482 = "hostingcloud.science"
        $link483 = "hostingcloud.stream"
        $link484 = "hostingcloud.trade"
        $link485 = "hostingcloud.win"
        $link486 = "minerad.com"
        $link487 = "coin-cube.com"
        $link488 = "coin-services.info"
        $link489 = "service4refresh.info"
        $link490 = "money-maker-script.info"
        $link491 = "money-maker-default.info"
        $link492 = "money-maker-default.info"
        $link493 = "de-ner-mi-nis4.info"
        $link494 = "de-nis-ner-mi-5.info"
        $link495 = "de-mi-nis-ner2.info"
        $link496 = "de-mi-nis-ner.info"
        $link497 = "mi-de-ner-nis3.info"
        $link498 = "s2.soodatmish.com"
        $link499 = "s2.thersprens.com"
        $link500 = "play.feesocrald.com"
        $link501 = "cdn1.pebx.pl"
        $link502 = "play.nexioniect.com"
        $link503 = "play.besstahete.info"
        $link504 = "s2.myregeneaf.com"
        $link505 = "s3.myregeneaf.com"
        $link506 = "reauthenticator.com"
        $link507 = "rock.reauthenticator.com"
        $link508 = "serv1swork.com"
        $link509 = "str1kee.com"
        $link510 = "f1tbit.com"
        $link511 = "g1thub.com"
        $link512 = "swiftmining.win"
        $link513 = "cashbeet.com"
        $link514 = "wmtech.website"
        $link515 = "www.notmining.org"
        $link516 = "coinminingonline.com"
        $link517 = "alflying.bid"
        $link518 = "alflying.date"
        $link519 = "alflying.win"
        $link520 = "anybest.host"
        $link521 = "anybest.pw"
        $link522 = "anybest.site"
        $link523 = "anybest.space"
        $link524 = "dubester.pw"
        $link525 = "dubester.site"
        $link526 = "dubester.space"
        $link527 = "flightsy.bid"
        $link528 = "flightsy.date"
        $link529 = "flightsy.win"
        $link530 = "flighty.win"
        $link531 = "flightzy.bid"
        $link532 = "flightzy.date"
        $link533 = "flightzy.win"
        $link534 = "gettate.date"
        $link535 = "gettate.faith"
        $link536 = "gettate.racing"
        $link537 = "mighbest.host"
        $link538 = "mighbest.pw"
        $link539 = "mighbest.site"
        $link540 = "zymerget.bid"
        $link541 = "zymerget.date"
        $link542 = "zymerget.faith"
        $link543 = "zymerget.party"
        $link544 = "zymerget.stream"
        $link545 = "zymerget.win"
        $link546 = "statdynamic.com"
        $link547 = "alpha.nimiqpool.com"
        $link548 = "api.miner.beeppool.org"
        $link549 = "beatingbytes.com"
        $link550 = "besocial.online"
        $link551 = "beta.nimiqpool.com"
        $link552 = "bulls.nimiqpool.com"
        $link553 = "de1.eu.nimiqpool.com"
        $link554 = "ethmedialab.info"
        $link555 = "feilding.nimiqpool.com"
        $link556 = "foxton.nimiqpool.com"
        $link557 = "ganymed.beeppool.org"
        $link558 = "himatangi.nimiqpool.com"
        $link559 = "levin.nimiqpool.com"
        $link560 = "mine.terorie.com"
        $link561 = "miner-1.team.nimiq.agency"
        $link562 = "miner-10.team.nimiq.agency"
        $link563 = "miner-11.team.nimiq.agency"
        $link564 = "miner-12.team.nimiq.agency"
        $link565 = "miner-13.team.nimiq.agency"
        $link566 = "miner-14.team.nimiq.agency"
        $link567 = "miner-15.team.nimiq.agency"
        $link568 = "miner-16.team.nimiq.agency"
        $link569 = "miner-17.team.nimiq.agency"
        $link570 = "miner-18.team.nimiq.agency"
        $link571 = "miner-19.team.nimiq.agency"
        $link572 = "miner-2.team.nimiq.agency"
        $link573 = "miner-3.team.nimiq.agency"
        $link574 = "miner-4.team.nimiq.agency"
        $link575 = "miner-5.team.nimiq.agency"
        $link576 = "miner-6.team.nimiq.agency"
        $link577 = "miner-7.team.nimiq.agency"
        $link578 = "miner-8.team.nimiq.agency"
        $link579 = "miner-9.team.nimiq.agency"
        $link580 = "miner-deu-1.inf.nimiq.network"
        $link581 = "miner-deu-2.inf.nimiq.network"
        $link582 = "miner-deu-3.inf.nimiq.network"
        $link583 = "miner-deu-4.inf.nimiq.network"
        $link584 = "miner-deu-5.inf.nimiq.network"
        $link585 = "miner-deu-6.inf.nimiq.network"
        $link586 = "miner-deu-7.inf.nimiq.network"
        $link587 = "miner-deu-8.inf.nimiq.network"
        $link588 = "miner.beeppool.org"
        $link589 = "miner.nimiq.com"
        $link590 = "mon-deu-1.inf.nimiq.network"
        $link591 = "mon-deu-2.inf.nimiq.network"
        $link592 = "mon-deu-3.inf.nimiq.network"
        $link593 = "mon-fra-1.inf.nimiq.network"
        $link594 = "mon-fra-2.inf.nimiq.network"
        $link595 = "mon-gbr-1.inf.nimiq.network"
        $link596 = "nimiq.terorie.com"
        $link597 = "nimiqpool.com"
        $link598 = "nimiqtest.ml"
        $link599 = "ninaning.com"
        $link600 = "node.alpha.nimiqpool.com"
        $link601 = "node.nimiqpool.com"
        $link602 = "nodeb.nimiqpool.com"
        $link603 = "nodeone.nimiqpool.com"
        $link604 = "proxy-can-1.inf.nimiq.network"
        $link605 = "proxy-deu-1.inf.nimiq.network"
        $link606 = "proxy-deu-2.inf.nimiq.network"
        $link607 = "proxy-fra-1.inf.nimiq.network"
        $link608 = "proxy-fra-2.inf.nimiq.network"
        $link609 = "proxy-fra-3.inf.nimiq.network"
        $link610 = "proxy-gbr-1.inf.nimiq.network"
        $link611 = "proxy-gbr-2.inf.nimiq.network"
        $link612 = "proxy-pol-1.inf.nimiq.network"
        $link613 = "proxy-pol-2.inf.nimiq.network"
        $link614 = "script.nimiqpool.com"
        $link615 = "seed-1.nimiq-network.com"
        $link616 = "seed-1.nimiq.com"
        $link617 = "seed-1.nimiq.network"
        $link618 = "seed-10.nimiq-network.com"
        $link619 = "seed-10.nimiq.com"
        $link620 = "seed-10.nimiq.network"
        $link621 = "seed-11.nimiq-network.com"
        $link622 = "seed-11.nimiq.com"
        $link623 = "seed-11.nimiq.network"
        $link624 = "seed-12.nimiq-network.com"
        $link625 = "seed-12.nimiq.com"
        $link626 = "seed-12.nimiq.network"
        $link627 = "seed-13.nimiq-network.com"
        $link628 = "seed-13.nimiq.com"
        $link629 = "seed-13.nimiq.network"
        $link630 = "seed-14.nimiq-network.com"
        $link631 = "seed-14.nimiq.com"
        $link632 = "seed-14.nimiq.network"
        $link633 = "seed-15.nimiq-network.com"
        $link634 = "seed-15.nimiq.com"
        $link635 = "seed-15.nimiq.network"
        $link636 = "seed-16.nimiq-network.com"
        $link637 = "seed-16.nimiq.com"
        $link638 = "seed-16.nimiq.network"
        $link639 = "seed-17.nimiq-network.com"
        $link640 = "seed-17.nimiq.com"
        $link641 = "seed-17.nimiq.network"
        $link642 = "seed-18.nimiq-network.com"
        $link643 = "seed-18.nimiq.com"
        $link644 = "seed-18.nimiq.network"
        $link645 = "seed-19.nimiq-network.com"
        $link646 = "seed-19.nimiq.com"
        $link647 = "seed-19.nimiq.network"
        $link648 = "seed-2.nimiq-network.com"
        $link649 = "seed-2.nimiq.com"
        $link650 = "seed-2.nimiq.network"
        $link651 = "seed-20.nimiq-network.com"
        $link652 = "seed-20.nimiq.com"
        $link653 = "seed-20.nimiq.network"
        $link654 = "seed-3.nimiq-network.com"
        $link655 = "seed-3.nimiq.com"
        $link656 = "seed-3.nimiq.network"
        $link657 = "seed-4.nimiq-network.com"
        $link658 = "seed-4.nimiq.com"
        $link659 = "seed-4.nimiq.network"
        $link660 = "seed-5.nimiq-network.com"
        $link661 = "seed-5.nimiq.com"
        $link662 = "seed-5.nimiq.network"
        $link663 = "seed-6.nimiq-network.com"
        $link664 = "seed-6.nimiq.com"
        $link665 = "seed-6.nimiq.network"
        $link666 = "seed-7.nimiq-network.com"
        $link667 = "seed-7.nimiq.com"
        $link668 = "seed-7.nimiq.network"
        $link669 = "seed-8.nimiq-network.com"
        $link670 = "seed-8.nimiq.com"
        $link671 = "seed-8.nimiq.network"
        $link672 = "seed-9.nimiq-network.com"
        $link673 = "seed-9.nimiq.com"
        $link674 = "seed-9.nimiq.network"
        $link675 = "seed-can-1.inf.nimiq.network"
        $link676 = "seed-can-2.inf.nimiq.network"
        $link677 = "seed-deu-1.inf.nimiq.network"
        $link678 = "seed-deu-2.inf.nimiq.network"
        $link679 = "seed-deu-3.inf.nimiq.network"
        $link680 = "seed-deu-4.inf.nimiq.network"
        $link681 = "seed-fra-1.inf.nimiq.network"
        $link682 = "seed-fra-2.inf.nimiq.network"
        $link683 = "seed-fra-3.inf.nimiq.network"
        $link684 = "seed-fra-4.inf.nimiq.network"
        $link685 = "seed-fra-5.inf.nimiq.network"
        $link686 = "seed-fra-6.inf.nimiq.network"
        $link687 = "seed-gbr-1.inf.nimiq.network"
        $link688 = "seed-gbr-2.inf.nimiq.network"
        $link689 = "seed-gbr-3.inf.nimiq.network"
        $link690 = "seed-gbr-4.inf.nimiq.network"
        $link691 = "seed-pol-1.inf.nimiq.network"
        $link692 = "seed-pol-2.inf.nimiq.network"
        $link693 = "seed-pol-3.inf.nimiq.network"
        $link694 = "seed-pol-4.inf.nimiq.network"
        $link695 = "seed.nimiqpool.com"
        $link696 = "seed1.sushipool.com"
        $link697 = "shannon.nimiqpool.com"
        $link698 = "sunnimiq.cf"
        $link699 = "sunnimiq1.cf"
        $link700 = "sunnimiq2.cf"
        $link701 = "sunnimiq3.cf"
        $link702 = "sunnimiq4.cf"
        $link703 = "sunnimiq5.cf"
        $link704 = "sunnimiq6.cf"
        $link705 = "tokomaru.nimiqpool.com"
        $link706 = "whanganui.nimiqpool.com"
        $link707 = "www.besocial.online"
        $link708 = "nimiq.com"
        $link709 = "miner.nimiq.com"
        $link710 = "cdn.nimiq.com"
        $link711 = "jscoinminer.com"
        $link712 = "www.jscoinminer.com"
        $link713 = "azvjudwr.info"
        $link714 = "jroqvbvw.info"
        $link715 = "jyhfuqoh.info"
        $link716 = "kdowqlpt.info"
        $link717 = "xbasfbno.info"
        $link718 = "1beb2a44.space"
        $link719 = "300ca0d0.space"
        $link720 = "310ca263.space"
        $link721 = "320ca3f6.space"
        $link722 = "330ca589.space"
        $link723 = "340ca71c.space"
        $link724 = "360caa42.space"
        $link725 = "370cabd5.space"
        $link726 = "3c0cb3b4.space"
        $link727 = "3d0cb547.space"


        $js001 = "minercry.pt/processor.js"
        $js002 = "lib/crypta.js"
        $js003 = "authedmine.com/lib/authedmine.min.js"
        $js004 = "coin-hive.com/lib/coinhive.min.js"
        $js005 = "coinhive.com/media/miner.htm"
        $js006 = "coinhive.com/lib/coinhive.min.js"
        $js007 = "cryptaloot.pro/lib/crypta.js"
        $js008 = "webminerpool.com/miner.js"
        $js009 = "play.gramombird.com/app.js"
        $js010 = "CoinHive.User("
        $js011 = "CoinHive.Anonymous("
        $js012 = "CoinHive.Token("
        $js013 = "CoinHive"
        $js015 = "miner.start("
        $js016 = "coinhive_site_key"
        $js017 = "MinerPage.prototype.startStopMine("
        $js018 = "Android.onMiningStartedJS()"
        $js019 = "javascript:startminer("
        $js020 = "javascript:startMining()"
        $js021 = "javascript:stopMining()"
        $js022 = "CRLT.Anonymous("
        $js023 = "CoinImp.Anonymous("
        $js024 = "Client.Anonymous("
        $js025 = "NFMiner"
        $js026 = "deepMiner.Anonymous"
        $js027 = "javascript:document.getElementById('mining-start').click()"
        $js028 = "javascript:document.getElementById('mining-stop').click()"


        $lib001 = "libminer.so"
        $lib002 = "libcpuminer.so"
        $lib004 = "libcpuminer-neon.so"
        $lib005 = "libneondetect.so"
        $lib006 = "libjpegso.so"
        $lib007 = "libcpuminerneonpie.so"
        $lib008 = "libcpuminerneon.so"
        $lib009 = "libcpuminerpie.so"
        $lib010 = "libcpuminerx86.so"
        $lib011 = "libMINERWRAPPER.so"
        $lib012 = "libCPUCHECKER.so"
        $lib013 = "minerd"
        $lib014 = "minerd_neon"
        $lib015 = "minerd_regular"
        $lib016 = "libgl-render.so"
        $lib017 = "libminersdk-neondetect.so"
        $lib018 = "libminersdk-x86.so"
        $lib019 = "libminersdk.so"
        $lib020 = "libmonerujo.so"
        $lib021 = "xmrig"


        $api001 = "Lcom/kaching/kingforaday/service/CoinHiveIntentService"
        $api002 = "Lcom/theah64/coinhive/CoinHive"
        $api004 = "Lcom/bing/crymore/ch/model/GlobalConfig"
        $api005 = "Ler/upgrad/jio/jioupgrader/Coinhive"
        $api006 = "Lcom/mobeleader/spsapp/Fragment_Miner"
        $api007 = "Lcom/mobeleader/spsapp/SpsApp"
        $api008 = "Lcom/mobeleader/minerlib/MinerLib"
        $api009 = "Lcom/coinhiveminer/CoinHive"
        $api011 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/CoinHive"
        $api012 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/MoneroMiner"
        $api013 = "Lclub/mymedia/mobileminer/mining/coinhive/MoneroMiner"
        $api014 = "Lclub/mymedia/mobileminer/mining/litecoin/LiteCoinMiner"
        $api015 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/CoinHive"
        $api016 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/MoneroMiner"
        $api017 = "Lclub/mymedia/mobileminer/modules/mining/Miner"
        $api018 = "Lclub/mymedia/mobileminer/modules/mining/litecoin/LiteCoinMiner"
        $api019 = "Luk/co/wardworks/pocketminer/API/LitecoinPool/LitecoinPoolModal"
        $api020 = "Lcom/wiseplay/web/resources/CoinhiveBlock"
        $api021 = "Lcoinminerandroid/coinminer/cma/coinminerandroid"
        $api023 = "Lcom/minergate/miner/Miner"
        $api024 = "Lcom/minergate/miner/services/MinerService"
        $api025 = "startMiner"
        
	/*
        $misc001 = "kingforaday" 
        $misc002 = "fopaminer" 
        $misc003 = "gadgetium" 
        $misc004 = "coinhive" 
        $misc005 = "litecoin" 
        $misc006 = "stratum" 
        $misc007 = "ethereum" 
        $misc008 = "monero" 
        $misc009 = "cpuminer" 
        $misc010 = "cpu-miner" 
        $misc011 = "cpu_miner" 
        $misc012 = "monerise_builder" 
        $misc013 = "moneroocean.stream" 
        $misc014 = "ethonline.site" 
        $misc015 = "mineralt"
	*/




	condition:
	androguard.permission(/android.permission.INTERNET/) and 
	(
        androguard.url(/my.electroneum.com/i) or cuckoo.network.dns_lookup(/my.electroneum.com/i) or
        androguard.url(/api.electroneum.com/i) or cuckoo.network.dns_lookup(/api.electroneum.com/i) or
        androguard.url(/api.coinhive.com/i) or cuckoo.network.dns_lookup(/api.coinhive.com/i) or
        androguard.url(/ftp.coinhive-manager.com/i) or cuckoo.network.dns_lookup(/ftp.coinhive-manager.com/i) or
        androguard.url(/coinhive.com/i) or cuckoo.network.dns_lookup(/coinhive.com/i) or
        androguard.url(/coinhiver.com/i) or cuckoo.network.dns_lookup(/coinhiver.com/i) or
        androguard.url(/coinhives.com/i) or cuckoo.network.dns_lookup(/coinhives.com/i) or
        androguard.url(/coinhiveproxy.com/i) or cuckoo.network.dns_lookup(/coinhiveproxy.com/i) or
        androguard.url(/coinhive-proxy.party/i) or cuckoo.network.dns_lookup(/coinhive-proxy.party/i) or
        androguard.url(/coinhive-manager.com/i) or cuckoo.network.dns_lookup(/coinhive-manager.com/i) or
        androguard.url(/coinhive.info/i) or cuckoo.network.dns_lookup(/coinhive.info/i) or
        androguard.url(/coinhive.net/i) or cuckoo.network.dns_lookup(/coinhive.net/i) or
        androguard.url(/coinhive.org/i) or cuckoo.network.dns_lookup(/coinhive.org/i) or
        androguard.url(/apin.monerise.com/i) or cuckoo.network.dns_lookup(/apin.monerise.com/i) or
        androguard.url(/authedmine.eu/i) or cuckoo.network.dns_lookup(/authedmine.eu/i) or
        androguard.url(/authedmine.com/i) or cuckoo.network.dns_lookup(/authedmine.com/i) or
        androguard.url(/50million.club/i) or cuckoo.network.dns_lookup(/50million.club/i) or
        androguard.url(/primary.coinhuntr.com/i) or cuckoo.network.dns_lookup(/primary.coinhuntr.com/i) or
        androguard.url(/api.bitcoin.cz/i) or cuckoo.network.dns_lookup(/api.bitcoin.cz/i) or
        androguard.url(/cryptominingfarm.io/i) or cuckoo.network.dns_lookup(/cryptominingfarm.io/i) or
        androguard.url(/litecoinpool.org/i) or cuckoo.network.dns_lookup(/litecoinpool.org/i) or
        androguard.url(/us.litecoinpool.org/i) or cuckoo.network.dns_lookup(/us.litecoinpool.org/i) or
        androguard.url(/us2.litecoinpool.org/i) or cuckoo.network.dns_lookup(/us2.litecoinpool.org/i) or
        androguard.url(/www.rexminer.com\/mobil/i) or cuckoo.network.dns_lookup(/www.rexminer.com/i) or
        androguard.url(/www.megaproxylist.net\/appmonerominer\/minerxmr.aspx/i) or
        androguard.url(/pool.supportxmr.com/i) or cuckoo.network.dns_lookup(/pool.supportxmr.com/i) or
        androguard.url(/poolw.etnpooler.com/i) or cuckoo.network.dns_lookup(/poolw.etnpooler.com/i) or
        androguard.url(/xmr.nanopool.org/i) or cuckoo.network.dns_lookup(/xmr.nanopool.org/i) or
        androguard.url(/nyc01.supportxmr.com/i) or cuckoo.network.dns_lookup(/nyc01.supportxmr.com/i) or
        androguard.url(/hk01.supportxmr.com/i) or cuckoo.network.dns_lookup(/hk01.supportxmr.com/i) or
        androguard.url(/hk02.supportxmr.com/i) or cuckoo.network.dns_lookup(/hk02.supportxmr.com/i) or
        androguard.url(/fr04.supportxmr.com/i) or cuckoo.network.dns_lookup(/fr04.supportxmr.com/i) or
        androguard.url(/qrl.herominers.com/i) or cuckoo.network.dns_lookup(/qrl.herominers.com/i) or
        androguard.url(/akgpr.com\/Mining/i) or cuckoo.network.dns_lookup(/akgpr.com/i) or
        androguard.url(/www.buyguard.co\/sdk/i) or cuckoo.network.dns_lookup(/www.buyguard.co/i) or
        androguard.url(/mrpool.net/i) or cuckoo.network.dns_lookup(/mrpool.net/i) or
        androguard.url(/raw.githubusercontent.com\/cryptominesetting/i) or
        androguard.url(/miner.mobeleader.com\/miner.php/i) or cuckoo.network.dns_lookup(/miner.mobeleader.com/i) or
        androguard.url(/github.com\/C0nw0nk\/CoinHive/i) or
        androguard.url(/stratum+tcp:\/\/litecoinpool.org/i) or cuckoo.network.dns_lookup(/litecoinpool.org/i) or
        androguard.url(/stratum+tcp:\/\/eu.multipool.us/i) or cuckoo.network.dns_lookup(/eu.multipool.us/i) or
        androguard.url(/stratum+tcp:\/\/stratum.bitcoin.cz/i) or cuckoo.network.dns_lookup(/\stratum.bitcoin.cz/i) or
        androguard.url(/stratum+tcp:\/\/groestlcoin.biz/i) or cuckoo.network.dns_lookup(/groestlcoin.biz/i) or
        androguard.url(/com.puregoldapps.eth.mine/i) or cuckoo.network.dns_lookup(/com.puregoldapps.eth.mine/i) or
        androguard.url(/api.kanke365.com/i) or cuckoo.network.dns_lookup(/api.kanke365.com/i) or
        androguard.url(/cnhv.co/i) or cuckoo.network.dns_lookup(/cnhv.co/i) or
        androguard.url(/coin-hive.com/i) or cuckoo.network.dns_lookup(/coin-hive.com/i) or
        androguard.url(/coinhive.com/i) or cuckoo.network.dns_lookup(/coinhive.com/i) or
        androguard.url(/authedmine.com/i) or cuckoo.network.dns_lookup(/authedmine.com/i) or
        androguard.url(/api.jsecoin.com/i) or cuckoo.network.dns_lookup(/api.jsecoin.com/i) or
        androguard.url(/load.jsecoin.com/i) or cuckoo.network.dns_lookup(/load.jsecoin.com/i) or
        androguard.url(/server.jsecoin.com/i) or cuckoo.network.dns_lookup(/server.jsecoin.com/i) or
        androguard.url(/miner.pr0gramm.com/i) or cuckoo.network.dns_lookup(/miner.pr0gramm.com/i) or
        androguard.url(/minemytraffic.com/i) or cuckoo.network.dns_lookup(/minemytraffic.com/i) or
        androguard.url(/ppoi.org/i) or cuckoo.network.dns_lookup(/ppoi.org/i) or
        androguard.url(/projectpoi.com/i) or cuckoo.network.dns_lookup(/projectpoi.com/i) or
        androguard.url(/crypto-loot.com/i) or cuckoo.network.dns_lookup(/crypto-loot.com/i) or
        androguard.url(/cryptaloot.pro/i) or cuckoo.network.dns_lookup(/cryptaloot.pro/i) or
        androguard.url(/cryptoloot.pro/i) or cuckoo.network.dns_lookup(/cryptoloot.pro/i) or
        androguard.url(/coinerra.com/i) or cuckoo.network.dns_lookup(/coinerra.com/i) or
        androguard.url(/coin-have.com/i) or cuckoo.network.dns_lookup(/coin-have.com/i) or
        androguard.url(/minero.pw/i) or cuckoo.network.dns_lookup(/minero.pw/i) or
        androguard.url(/minero-proxy-01.now.sh/i) or cuckoo.network.dns_lookup(/minero-proxy-01.now.sh/i) or
        androguard.url(/minero-proxy-02.now.sh/i) or cuckoo.network.dns_lookup(/minero-proxy-02.now.sh/i) or
        androguard.url(/minero-proxy-03.now.sh/i) or cuckoo.network.dns_lookup(/minero-proxy-03.now.sh/i) or
        androguard.url(/api.inwemo.com/i) or cuckoo.network.dns_lookup(/api.inwemo.com/i) or
        androguard.url(/rocks.io/i) or cuckoo.network.dns_lookup(/rocks.io/i) or
        androguard.url(/adminer.com/i) or cuckoo.network.dns_lookup(/adminer.com/i) or
        androguard.url(/ad-miner.com/i) or cuckoo.network.dns_lookup(/ad-miner.com/i) or
        androguard.url(/jsccnn.com/i) or cuckoo.network.dns_lookup(/jsccnn.com/i) or
        androguard.url(/jscdndel.com/i) or cuckoo.network.dns_lookup(/jscdndel.com/i) or
        androguard.url(/coinhiveproxy.com/i) or cuckoo.network.dns_lookup(/coinhiveproxy.com/i) or
        androguard.url(/coinblind.com/i) or cuckoo.network.dns_lookup(/coinblind.com/i) or
        androguard.url(/coinnebula.com/i) or cuckoo.network.dns_lookup(/coinnebula.com/i) or
        androguard.url(/monerominer.rocks/i) or cuckoo.network.dns_lookup(/monerominer.rocks/i) or
        androguard.url(/cdn.cloudcoins.co/i) or cuckoo.network.dns_lookup(/cdn.cloudcoins.co/i) or
        androguard.url(/coinlab.biz/i) or cuckoo.network.dns_lookup(/coinlab.biz/i) or
        androguard.url(/go.megabanners.cf/i) or cuckoo.network.dns_lookup(/go.megabanners.cf/i) or
        androguard.url(/baiduccdn1.com/i) or cuckoo.network.dns_lookup(/baiduccdn1.com/i) or
        androguard.url(/wsp.marketgid.com/i) or cuckoo.network.dns_lookup(/wsp.marketgid.com/i) or
        androguard.url(/papoto.com/i) or cuckoo.network.dns_lookup(/papoto.com/i) or
        androguard.url(/flare-analytics.com/i) or cuckoo.network.dns_lookup(/flare-analytics.com/i) or
        androguard.url(/www.sparechange.io/i) or cuckoo.network.dns_lookup(/www.sparechange.io/i) or
        androguard.url(/static.sparechange.io/i) or cuckoo.network.dns_lookup(/static.sparechange.io/i) or
        androguard.url(/miner.nablabee.com/i) or cuckoo.network.dns_lookup(/miner.nablabee.com/i) or
        androguard.url(/m.anyfiles.ovh/i) or cuckoo.network.dns_lookup(/m.anyfiles.ovh/i) or
        androguard.url(/coinimp.com/i) or cuckoo.network.dns_lookup(/coinimp.com/i) or
        androguard.url(/coinimp.net/i) or cuckoo.network.dns_lookup(/coinimp.net/i) or
        androguard.url(/freecontent.bid/i) or cuckoo.network.dns_lookup(/freecontent.bid/i) or
        androguard.url(/freecontent.date/i) or cuckoo.network.dns_lookup(/freecontent.date/i) or
        androguard.url(/freecontent.faith/i) or cuckoo.network.dns_lookup(/freecontent.faith/i) or
        androguard.url(/freecontent.loan/i) or cuckoo.network.dns_lookup(/freecontent.loan/i) or
        androguard.url(/freecontent.racing/i) or cuckoo.network.dns_lookup(/freecontent.racing/i) or
        androguard.url(/freecontent.win/i) or cuckoo.network.dns_lookup(/freecontent.win/i) or
        androguard.url(/blockchained.party/i) or cuckoo.network.dns_lookup(/blockchained.party/i) or
        androguard.url(/hostingcloud.download/i) or cuckoo.network.dns_lookup(/hostingcloud.download/i) or
        androguard.url(/cryptonoter.com/i) or cuckoo.network.dns_lookup(/cryptonoter.com/i) or
        androguard.url(/mutuza.win/i) or cuckoo.network.dns_lookup(/mutuza.win/i) or
        androguard.url(/crypto-webminer.com/i) or cuckoo.network.dns_lookup(/crypto-webminer.com/i) or
        androguard.url(/cdn.adless.io/i) or cuckoo.network.dns_lookup(/cdn.adless.io/i) or
        androguard.url(/hegrinhar.com/i) or cuckoo.network.dns_lookup(/hegrinhar.com/i) or
        androguard.url(/verresof.com/i) or cuckoo.network.dns_lookup(/verresof.com/i) or
        androguard.url(/hemnes.win/i) or cuckoo.network.dns_lookup(/hemnes.win/i) or
        androguard.url(/tidafors.xyz/i) or cuckoo.network.dns_lookup(/tidafors.xyz/i) or
        androguard.url(/moneone.ga/i) or cuckoo.network.dns_lookup(/moneone.ga/i) or
        androguard.url(/plexcoin.info/i) or cuckoo.network.dns_lookup(/plexcoin.info/i) or
        androguard.url(/www.monkeyminer.net/i) or cuckoo.network.dns_lookup(/www.monkeyminer.net/i) or
        androguard.url(/go2.mercy.ga/i) or cuckoo.network.dns_lookup(/go2.mercy.ga/i) or
        androguard.url(/coinpirate.cf/i) or cuckoo.network.dns_lookup(/coinpirate.cf/i) or
        androguard.url(/d.cpufan.club/i) or cuckoo.network.dns_lookup(/d.cpufan.club/i) or
        androguard.url(/krb.devphp.org.ua/i) or cuckoo.network.dns_lookup(/krb.devphp.org.ua/i) or
        androguard.url(/nfwebminer.com/i) or cuckoo.network.dns_lookup(/nfwebminer.com/i) or
        androguard.url(/cfcdist.gdn/i) or cuckoo.network.dns_lookup(/cfcdist.gdn/i) or
        androguard.url(/node.cfcdist.gdn/i) or cuckoo.network.dns_lookup(/node.cfcdist.gdn/i) or
        androguard.url(/webxmr.com/i) or cuckoo.network.dns_lookup(/webxmr.com/i) or
        androguard.url(/xmr.mining.best/i) or cuckoo.network.dns_lookup(/xmr.mining.best/i) or
        androguard.url(/webminepool.com/i) or cuckoo.network.dns_lookup(/webminepool.com/i) or
        androguard.url(/webminepool.tk/i) or cuckoo.network.dns_lookup(/webminepool.tk/i) or
        androguard.url(/hive.tubetitties.com/i) or cuckoo.network.dns_lookup(/hive.tubetitties.com/i) or
        androguard.url(/playerassets.info/i) or cuckoo.network.dns_lookup(/playerassets.info/i) or
        androguard.url(/tokyodrift.ga/i) or cuckoo.network.dns_lookup(/tokyodrift.ga/i) or
        androguard.url(/webassembly.stream/i) or cuckoo.network.dns_lookup(/webassembly.stream/i) or
        androguard.url(/www.webassembly.stream/i) or cuckoo.network.dns_lookup(/www.webassembly.stream/i) or
        androguard.url(/okeyletsgo.ml/i) or cuckoo.network.dns_lookup(/okeyletsgo.ml/i) or
        androguard.url(/candid.zone/i) or cuckoo.network.dns_lookup(/candid.zone/i) or
        androguard.url(/webmine.pro/i) or cuckoo.network.dns_lookup(/webmine.pro/i) or
        androguard.url(/andlache.com/i) or cuckoo.network.dns_lookup(/andlache.com/i) or
        androguard.url(/bablace.com/i) or cuckoo.network.dns_lookup(/bablace.com/i) or
        androguard.url(/bewaslac.com/i) or cuckoo.network.dns_lookup(/bewaslac.com/i) or
        androguard.url(/biberukalap.com/i) or cuckoo.network.dns_lookup(/biberukalap.com/i) or
        androguard.url(/bowithow.com/i) or cuckoo.network.dns_lookup(/bowithow.com/i) or
        androguard.url(/butcalve.com/i) or cuckoo.network.dns_lookup(/butcalve.com/i) or
        androguard.url(/evengparme.com/i) or cuckoo.network.dns_lookup(/evengparme.com/i) or
        androguard.url(/gridiogrid.com/i) or cuckoo.network.dns_lookup(/gridiogrid.com/i) or
        androguard.url(/hatcalter.com/i) or cuckoo.network.dns_lookup(/hatcalter.com/i) or
        androguard.url(/kedtise.com/i) or cuckoo.network.dns_lookup(/kedtise.com/i) or
        androguard.url(/ledinund.com/i) or cuckoo.network.dns_lookup(/ledinund.com/i) or
        androguard.url(/nathetsof.com/i) or cuckoo.network.dns_lookup(/nathetsof.com/i) or
        androguard.url(/renhertfo.com/i) or cuckoo.network.dns_lookup(/renhertfo.com/i) or
        androguard.url(/rintindown.com/i) or cuckoo.network.dns_lookup(/rintindown.com/i) or
        androguard.url(/sparnove.com/i) or cuckoo.network.dns_lookup(/sparnove.com/i) or
        androguard.url(/witthethim.com/i) or cuckoo.network.dns_lookup(/witthethim.com/i) or
        androguard.url(/1q2w3.fun/i) or cuckoo.network.dns_lookup(/1q2w3.fun/i) or
        androguard.url(/1q2w3.me/i) or cuckoo.network.dns_lookup(/1q2w3.me/i) or
        androguard.url(/bjorksta.men/i) or cuckoo.network.dns_lookup(/bjorksta.men/i) or
        androguard.url(/crypto.csgocpu.com/i) or cuckoo.network.dns_lookup(/crypto.csgocpu.com/i) or
        androguard.url(/noblock.pro/i) or cuckoo.network.dns_lookup(/noblock.pro/i) or
        androguard.url(/miner.cryptobara.com/i) or cuckoo.network.dns_lookup(/miner.cryptobara.com/i) or
        androguard.url(/digger.cryptobara.com/i) or cuckoo.network.dns_lookup(/digger.cryptobara.com/i) or
        androguard.url(/dev.cryptobara.com/i) or cuckoo.network.dns_lookup(/dev.cryptobara.com/i) or
        androguard.url(/reservedoffers.club/i) or cuckoo.network.dns_lookup(/reservedoffers.club/i) or
        androguard.url(/mine.torrent.pw/i) or cuckoo.network.dns_lookup(/mine.torrent.pw/i) or
        androguard.url(/host.d-ns.ga/i) or cuckoo.network.dns_lookup(/host.d-ns.ga/i) or
        androguard.url(/abc.pema.cl/i) or cuckoo.network.dns_lookup(/abc.pema.cl/i) or
        androguard.url(/js.nahnoji.cz/i) or cuckoo.network.dns_lookup(/js.nahnoji.cz/i) or
        androguard.url(/mine.nahnoji.cz/i) or cuckoo.network.dns_lookup(/mine.nahnoji.cz/i) or
        androguard.url(/webmine.cz/i) or cuckoo.network.dns_lookup(/webmine.cz/i) or
        androguard.url(/www.webmine.cz/i) or cuckoo.network.dns_lookup(/www.webmine.cz/i) or
        androguard.url(/intactoffers.club/i) or cuckoo.network.dns_lookup(/intactoffers.club/i) or
        androguard.url(/analytics.blue/i) or cuckoo.network.dns_lookup(/analytics.blue/i) or
        androguard.url(/smectapop12.pl/i) or cuckoo.network.dns_lookup(/smectapop12.pl/i) or
        androguard.url(/berserkpl.net.pl/i) or cuckoo.network.dns_lookup(/berserkpl.net.pl/i) or
        androguard.url(/hodlers.party/i) or cuckoo.network.dns_lookup(/hodlers.party/i) or
        androguard.url(/hodling.faith/i) or cuckoo.network.dns_lookup(/hodling.faith/i) or
        androguard.url(/chainblock.science/i) or cuckoo.network.dns_lookup(/chainblock.science/i) or
        androguard.url(/minescripts.info/i) or cuckoo.network.dns_lookup(/minescripts.info/i) or
        androguard.url(/cdn.minescripts.info/i) or cuckoo.network.dns_lookup(/cdn.minescripts.info/i) or
        androguard.url(/miner.nablabee.com/i) or cuckoo.network.dns_lookup(/miner.nablabee.com/i) or
        androguard.url(/wss.nablabee.com/i) or cuckoo.network.dns_lookup(/wss.nablabee.com/i) or
        androguard.url(/clickwith.bid/i) or cuckoo.network.dns_lookup(/clickwith.bid/i) or
        androguard.url(/dronml.ml/i) or cuckoo.network.dns_lookup(/dronml.ml/i) or
        androguard.url(/niematego.tk/i) or cuckoo.network.dns_lookup(/niematego.tk/i) or
        androguard.url(/tulip18.com/i) or cuckoo.network.dns_lookup(/tulip18.com/i) or
        androguard.url(/p.estream.to/i) or cuckoo.network.dns_lookup(/p.estream.to/i) or
        androguard.url(/didnkinrab.com/i) or cuckoo.network.dns_lookup(/didnkinrab.com/i) or
        androguard.url(/ledhenone.com/i) or cuckoo.network.dns_lookup(/ledhenone.com/i) or
        androguard.url(/losital.ru/i) or cuckoo.network.dns_lookup(/losital.ru/i) or
        androguard.url(/mebablo.com/i) or cuckoo.network.dns_lookup(/mebablo.com/i) or
        androguard.url(/moonsade.com/i) or cuckoo.network.dns_lookup(/moonsade.com/i) or
        androguard.url(/nebabrop.com/i) or cuckoo.network.dns_lookup(/nebabrop.com/i) or
        androguard.url(/pearno.com/i) or cuckoo.network.dns_lookup(/pearno.com/i) or
        androguard.url(/rintinwa.com/i) or cuckoo.network.dns_lookup(/rintinwa.com/i) or
        androguard.url(/willacrit.com/i) or cuckoo.network.dns_lookup(/willacrit.com/i) or
        androguard.url(/www2.adfreetv.ch/i) or cuckoo.network.dns_lookup(/www2.adfreetv.ch/i) or
        androguard.url(/minr.pw/i) or cuckoo.network.dns_lookup(/minr.pw/i) or
        androguard.url(/new.minr.pw/i) or cuckoo.network.dns_lookup(/new.minr.pw/i) or
        androguard.url(/test.minr.pw/i) or cuckoo.network.dns_lookup(/test.minr.pw/i) or
        androguard.url(/staticsfs.host/i) or cuckoo.network.dns_lookup(/staticsfs.host/i) or
        androguard.url(/cdn-code.host/i) or cuckoo.network.dns_lookup(/cdn-code.host/i) or
        androguard.url(/g-content.bid/i) or cuckoo.network.dns_lookup(/g-content.bid/i) or
        androguard.url(/ad.g-content.bid/i) or cuckoo.network.dns_lookup(/ad.g-content.bid/i) or
        androguard.url(/cdn.static-cnt.bid/i) or cuckoo.network.dns_lookup(/cdn.static-cnt.bid/i) or
        androguard.url(/cnt.statistic.date/i) or cuckoo.network.dns_lookup(/cnt.statistic.date/i) or
        androguard.url(/jquery-uim.download/i) or cuckoo.network.dns_lookup(/jquery-uim.download/i) or
        androguard.url(/cdn.jquery-uim.download/i) or cuckoo.network.dns_lookup(/cdn.jquery-uim.download/i) or
        androguard.url(/cdn-jquery.host/i) or cuckoo.network.dns_lookup(/cdn-jquery.host/i) or
        androguard.url(/p1.interestingz.pw/i) or cuckoo.network.dns_lookup(/p1.interestingz.pw/i) or
        androguard.url(/kippbeak.cf/i) or cuckoo.network.dns_lookup(/kippbeak.cf/i) or
        androguard.url(/pasoherb.gq/i) or cuckoo.network.dns_lookup(/pasoherb.gq/i) or
        androguard.url(/axoncoho.tk/i) or cuckoo.network.dns_lookup(/axoncoho.tk/i) or
        androguard.url(/depttake.ga/i) or cuckoo.network.dns_lookup(/depttake.ga/i) or
        androguard.url(/flophous.cf/i) or cuckoo.network.dns_lookup(/flophous.cf/i) or
        androguard.url(/pr0gram.org/i) or cuckoo.network.dns_lookup(/pr0gram.org/i) or
        androguard.url(/authedmine.eu/i) or cuckoo.network.dns_lookup(/authedmine.eu/i) or
        androguard.url(/www.monero-miner.com/i) or cuckoo.network.dns_lookup(/www.monero-miner.com/i) or
        androguard.url(/www.datasecu.download/i) or cuckoo.network.dns_lookup(/www.datasecu.download/i) or
        androguard.url(/www.jquery-cdn.download/i) or cuckoo.network.dns_lookup(/www.jquery-cdn.download/i) or
        androguard.url(/www.etzbnfuigipwvs.ru/i) or cuckoo.network.dns_lookup(/www.etzbnfuigipwvs.ru/i) or
        androguard.url(/www.terethat.ru/i) or cuckoo.network.dns_lookup(/www.terethat.ru/i) or
        androguard.url(/freshrefresher.com/i) or cuckoo.network.dns_lookup(/freshrefresher.com/i) or
        androguard.url(/api.pzoifaum.info/i) or cuckoo.network.dns_lookup(/api.pzoifaum.info/i) or
        androguard.url(/ws.pzoifaum.info/i) or cuckoo.network.dns_lookup(/ws.pzoifaum.info/i) or
        androguard.url(/api.bhzejltg.info/i) or cuckoo.network.dns_lookup(/api.bhzejltg.info/i) or
        androguard.url(/ws.bhzejltg.info/i) or cuckoo.network.dns_lookup(/ws.bhzejltg.info/i) or
        androguard.url(/d.cfcnet.top/i) or cuckoo.network.dns_lookup(/d.cfcnet.top/i) or
        androguard.url(/vip.cfcnet.top/i) or cuckoo.network.dns_lookup(/vip.cfcnet.top/i) or
        androguard.url(/eu.cfcnet.top/i) or cuckoo.network.dns_lookup(/eu.cfcnet.top/i) or
        androguard.url(/as.cfcnet.top/i) or cuckoo.network.dns_lookup(/as.cfcnet.top/i) or
        androguard.url(/us.cfcnet.top/i) or cuckoo.network.dns_lookup(/us.cfcnet.top/i) or
        androguard.url(/eu.cfcdist.loan/i) or cuckoo.network.dns_lookup(/eu.cfcdist.loan/i) or
        androguard.url(/as.cfcdist.loan/i) or cuckoo.network.dns_lookup(/as.cfcdist.loan/i) or
        androguard.url(/us.cfcdist.loan/i) or cuckoo.network.dns_lookup(/us.cfcdist.loan/i) or
        androguard.url(/gustaver.ddns.net/i) or cuckoo.network.dns_lookup(/gustaver.ddns.net/i) or
        androguard.url(/worker.salon.com/i) or cuckoo.network.dns_lookup(/worker.salon.com/i) or
        androguard.url(/s2.appelamule.com/i) or cuckoo.network.dns_lookup(/s2.appelamule.com/i) or
        androguard.url(/mepirtedic.com/i) or cuckoo.network.dns_lookup(/mepirtedic.com/i) or
        androguard.url(/cdn.streambeam.io/i) or cuckoo.network.dns_lookup(/cdn.streambeam.io/i) or
        androguard.url(/adzjzewsma.cf/i) or cuckoo.network.dns_lookup(/adzjzewsma.cf/i) or
        androguard.url(/ffinwwfpqi.gq/i) or cuckoo.network.dns_lookup(/ffinwwfpqi.gq/i) or
        androguard.url(/ininmacerad.pro/i) or cuckoo.network.dns_lookup(/ininmacerad.pro/i) or
        androguard.url(/mhiobjnirs.gq/i) or cuckoo.network.dns_lookup(/mhiobjnirs.gq/i) or
        androguard.url(/open-hive-server-1.pp.ua/i) or cuckoo.network.dns_lookup(/open-hive-server-1.pp.ua/i) or
        androguard.url(/pool.hws.ru/i) or cuckoo.network.dns_lookup(/pool.hws.ru/i) or
        androguard.url(/pool.etn.spacepools.org/i) or cuckoo.network.dns_lookup(/pool.etn.spacepools.org/i) or
        androguard.url(/api.aalbbh84.info/i) or cuckoo.network.dns_lookup(/api.aalbbh84.info/i) or
        androguard.url(/www.aymcsx.ru/i) or cuckoo.network.dns_lookup(/www.aymcsx.ru/i) or
        androguard.url(/aeros01.tk/i) or cuckoo.network.dns_lookup(/aeros01.tk/i) or
        androguard.url(/aeros02.tk/i) or cuckoo.network.dns_lookup(/aeros02.tk/i) or
        androguard.url(/aeros03.tk/i) or cuckoo.network.dns_lookup(/aeros03.tk/i) or
        androguard.url(/aeros04.tk/i) or cuckoo.network.dns_lookup(/aeros04.tk/i) or
        androguard.url(/aeros05.tk/i) or cuckoo.network.dns_lookup(/aeros05.tk/i) or
        androguard.url(/aeros06.tk/i) or cuckoo.network.dns_lookup(/aeros06.tk/i) or
        androguard.url(/aeros07.tk/i) or cuckoo.network.dns_lookup(/aeros07.tk/i) or
        androguard.url(/aeros08.tk/i) or cuckoo.network.dns_lookup(/aeros08.tk/i) or
        androguard.url(/aeros09.tk/i) or cuckoo.network.dns_lookup(/aeros09.tk/i) or
        androguard.url(/aeros10.tk/i) or cuckoo.network.dns_lookup(/aeros10.tk/i) or
        androguard.url(/aeros11.tk/i) or cuckoo.network.dns_lookup(/aeros11.tk/i) or
        androguard.url(/aeros12.tk/i) or cuckoo.network.dns_lookup(/aeros12.tk/i) or
        androguard.url(/npcdn1.now.sh/i) or cuckoo.network.dns_lookup(/npcdn1.now.sh/i) or
        androguard.url(/mxcdn2.now.sh/i) or cuckoo.network.dns_lookup(/mxcdn2.now.sh/i) or
        androguard.url(/sxcdn6.now.sh/i) or cuckoo.network.dns_lookup(/sxcdn6.now.sh/i) or
        androguard.url(/mxcdn1.now.sh/i) or cuckoo.network.dns_lookup(/mxcdn1.now.sh/i) or
        androguard.url(/sxcdn02.now.sh/i) or cuckoo.network.dns_lookup(/sxcdn02.now.sh/i) or
        androguard.url(/sxcdn4.now.sh/i) or cuckoo.network.dns_lookup(/sxcdn4.now.sh/i) or
        androguard.url(/jqcdn2.herokuapp.com/i) or cuckoo.network.dns_lookup(/jqcdn2.herokuapp.com/i) or
        androguard.url(/sxcdn1.herokuapp.com/i) or cuckoo.network.dns_lookup(/sxcdn1.herokuapp.com/i) or
        androguard.url(/sxcdn5.herokuapp.com/i) or cuckoo.network.dns_lookup(/sxcdn5.herokuapp.com/i) or
        androguard.url(/wpcdn1.herokuapp.com/i) or cuckoo.network.dns_lookup(/wpcdn1.herokuapp.com/i) or
        androguard.url(/jqcdn01.herokuapp.com/i) or cuckoo.network.dns_lookup(/jqcdn01.herokuapp.com/i) or
        androguard.url(/jqcdn03.herokuapp.com/i) or cuckoo.network.dns_lookup(/jqcdn03.herokuapp.com/i) or
        androguard.url(/1q2w3.website/i) or cuckoo.network.dns_lookup(/1q2w3.website/i) or
        androguard.url(/video.videos.vidto.me/i) or cuckoo.network.dns_lookup(/video.videos.vidto.me/i) or
        androguard.url(/play.play1.videos.vidto.me/i) or cuckoo.network.dns_lookup(/play.play1.videos.vidto.me/i) or
        androguard.url(/playe.vidto.se/i) or cuckoo.network.dns_lookup(/playe.vidto.se/i) or
        androguard.url(/video.streaming.estream.to/i) or cuckoo.network.dns_lookup(/video.streaming.estream.to/i) or
        androguard.url(/eth-pocket.de/i) or cuckoo.network.dns_lookup(/eth-pocket.de/i) or
        androguard.url(/xvideosharing.site/i) or cuckoo.network.dns_lookup(/xvideosharing.site/i) or
        androguard.url(/bestcoinsignals.com/i) or cuckoo.network.dns_lookup(/bestcoinsignals.com/i) or
        androguard.url(/eucsoft.com/i) or cuckoo.network.dns_lookup(/eucsoft.com/i) or
        androguard.url(/traviilo.com/i) or cuckoo.network.dns_lookup(/traviilo.com/i) or
        androguard.url(/wasm24.ru/i) or cuckoo.network.dns_lookup(/wasm24.ru/i) or
        androguard.url(/xmr.cool/i) or cuckoo.network.dns_lookup(/xmr.cool/i) or
        androguard.url(/api.netflare.info/i) or cuckoo.network.dns_lookup(/api.netflare.info/i) or
        androguard.url(/cdnjs.cloudflane.com/i) or cuckoo.network.dns_lookup(/cdnjs.cloudflane.com/i) or
        androguard.url(/www.cloudflane.com/i) or cuckoo.network.dns_lookup(/www.cloudflane.com/i) or
        androguard.url(/clgserv.pro/i) or cuckoo.network.dns_lookup(/clgserv.pro/i) or
        androguard.url(/hide.ovh/i) or cuckoo.network.dns_lookup(/hide.ovh/i) or
        androguard.url(/graftpool.ovh/i) or cuckoo.network.dns_lookup(/graftpool.ovh/i) or
        androguard.url(/encoding.ovh/i) or cuckoo.network.dns_lookup(/encoding.ovh/i) or
        androguard.url(/altavista.ovh/i) or cuckoo.network.dns_lookup(/altavista.ovh/i) or
        androguard.url(/scaleway.ovh/i) or cuckoo.network.dns_lookup(/scaleway.ovh/i) or
        androguard.url(/nexttime.ovh/i) or cuckoo.network.dns_lookup(/nexttime.ovh/i) or
        androguard.url(/never.ovh/i) or cuckoo.network.dns_lookup(/never.ovh/i) or
        androguard.url(/2giga.download/i) or cuckoo.network.dns_lookup(/2giga.download/i) or
        androguard.url(/support.2giga.link/i) or cuckoo.network.dns_lookup(/support.2giga.link/i) or
        androguard.url(/webminerpool.com/i) or cuckoo.network.dns_lookup(/webminerpool.com/i) or
        androguard.url(/minercry.pt/i) or cuckoo.network.dns_lookup(/minercry.pt/i) or
        androguard.url(/adplusplus.fr/i) or cuckoo.network.dns_lookup(/adplusplus.fr/i) or
        androguard.url(/ethtrader.de/i) or cuckoo.network.dns_lookup(/ethtrader.de/i) or
        androguard.url(/gobba.myeffect.net/i) or cuckoo.network.dns_lookup(/gobba.myeffect.net/i) or
        androguard.url(/bauersagtnein.myeffect.net/i) or cuckoo.network.dns_lookup(/bauersagtnein.myeffect.net/i) or
        androguard.url(/besti.ga/i) or cuckoo.network.dns_lookup(/besti.ga/i) or
        androguard.url(/jurty.ml/i) or cuckoo.network.dns_lookup(/jurty.ml/i) or
        androguard.url(/jurtym.cf/i) or cuckoo.network.dns_lookup(/jurtym.cf/i) or
        androguard.url(/mfio.cf/i) or cuckoo.network.dns_lookup(/mfio.cf/i) or
        androguard.url(/mwor.gq/i) or cuckoo.network.dns_lookup(/mwor.gq/i) or
        androguard.url(/oei1.gq/i) or cuckoo.network.dns_lookup(/oei1.gq/i) or
        androguard.url(/wordc.ga/i) or cuckoo.network.dns_lookup(/wordc.ga/i) or
        androguard.url(/berateveng.ru/i) or cuckoo.network.dns_lookup(/berateveng.ru/i) or
        androguard.url(/ctlrnwbv.ru/i) or cuckoo.network.dns_lookup(/ctlrnwbv.ru/i) or
        androguard.url(/ermaseuc.ru/i) or cuckoo.network.dns_lookup(/ermaseuc.ru/i) or
        androguard.url(/kdmkauchahynhrs.ru/i) or cuckoo.network.dns_lookup(/kdmkauchahynhrs.ru/i) or
        androguard.url(/uoldid.ru/i) or cuckoo.network.dns_lookup(/uoldid.ru/i) or
        androguard.url(/jqrcdn.download/i) or cuckoo.network.dns_lookup(/jqrcdn.download/i) or
        androguard.url(/jqassets.download/i) or cuckoo.network.dns_lookup(/jqassets.download/i) or
        androguard.url(/jqcdn.download/i) or cuckoo.network.dns_lookup(/jqcdn.download/i) or
        androguard.url(/jquerrycdn.download/i) or cuckoo.network.dns_lookup(/jquerrycdn.download/i) or
        androguard.url(/jqwww.download/i) or cuckoo.network.dns_lookup(/jqwww.download/i) or
        androguard.url(/lightminer.co/i) or cuckoo.network.dns_lookup(/lightminer.co/i) or
        androguard.url(/www.lightminer.co/i) or cuckoo.network.dns_lookup(/www.lightminer.co/i) or
        androguard.url(/browsermine.com/i) or cuckoo.network.dns_lookup(/browsermine.com/i) or
        androguard.url(/api.browsermine.com/i) or cuckoo.network.dns_lookup(/api.browsermine.com/i) or
        androguard.url(/mlib.browsermine.com/i) or cuckoo.network.dns_lookup(/mlib.browsermine.com/i) or
        androguard.url(/bmst.pw/i) or cuckoo.network.dns_lookup(/bmst.pw/i) or
        androguard.url(/bmnr.pw/i) or cuckoo.network.dns_lookup(/bmnr.pw/i) or
        androguard.url(/bmcm.pw/i) or cuckoo.network.dns_lookup(/bmcm.pw/i) or
        androguard.url(/bmcm.ml/i) or cuckoo.network.dns_lookup(/bmcm.ml/i) or
        androguard.url(/videoplayer2.xyz/i) or cuckoo.network.dns_lookup(/videoplayer2.xyz/i) or
        androguard.url(/play.video2.stream.vidzi.tv/i) or cuckoo.network.dns_lookup(/play.video2.stream.vidzi.tv/i) or
        androguard.url(/001.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/001.0x1f4b0.com/i) or
        androguard.url(/002.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/002.0x1f4b0.com/i) or
        androguard.url(/003.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/003.0x1f4b0.com/i) or
        androguard.url(/004.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/004.0x1f4b0.com/i) or
        androguard.url(/005.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/005.0x1f4b0.com/i) or
        androguard.url(/006.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/006.0x1f4b0.com/i) or
        androguard.url(/007.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/007.0x1f4b0.com/i) or
        androguard.url(/008.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/008.0x1f4b0.com/i) or
        androguard.url(/authedwebmine.cz/i) or cuckoo.network.dns_lookup(/authedwebmine.cz/i) or
        androguard.url(/www.authedwebmine.cz/i) or cuckoo.network.dns_lookup(/www.authedwebmine.cz/i) or
        androguard.url(/skencituer.com/i) or cuckoo.network.dns_lookup(/skencituer.com/i) or
        androguard.url(/site.flashx.cc/i) or cuckoo.network.dns_lookup(/site.flashx.cc/i) or
        androguard.url(/play1.flashx.pw/i) or cuckoo.network.dns_lookup(/play1.flashx.pw/i) or
        androguard.url(/play2.flashx.pw/i) or cuckoo.network.dns_lookup(/play2.flashx.pw/i) or
        androguard.url(/play4.flashx.pw/i) or cuckoo.network.dns_lookup(/play4.flashx.pw/i) or
        androguard.url(/play5.flashx.pw/i) or cuckoo.network.dns_lookup(/play5.flashx.pw/i) or
        androguard.url(/js.vidoza.net/i) or cuckoo.network.dns_lookup(/js.vidoza.net/i) or
        androguard.url(/mm.zubovskaya-banya.ru/i) or cuckoo.network.dns_lookup(/mm.zubovskaya-banya.ru/i) or
        androguard.url(/mysite.irkdsu.ru/i) or cuckoo.network.dns_lookup(/mysite.irkdsu.ru/i) or
        androguard.url(/play.estream.nu/i) or cuckoo.network.dns_lookup(/play.estream.nu/i) or
        androguard.url(/play.estream.to/i) or cuckoo.network.dns_lookup(/play.estream.to/i) or
        androguard.url(/play.estream.xyz/i) or cuckoo.network.dns_lookup(/play.estream.xyz/i) or
        androguard.url(/play.play.estream.nu/i) or cuckoo.network.dns_lookup(/play.play.estream.nu/i) or
        androguard.url(/play.play.estream.to/i) or cuckoo.network.dns_lookup(/play.play.estream.to/i) or
        androguard.url(/play.play.estream.xyz/i) or cuckoo.network.dns_lookup(/play.play.estream.xyz/i) or
        androguard.url(/play.tainiesonline.pw/i) or cuckoo.network.dns_lookup(/play.tainiesonline.pw/i) or
        androguard.url(/play.vidzi.tv/i) or cuckoo.network.dns_lookup(/play.vidzi.tv/i) or
        androguard.url(/play.pampopholf.com/i) or cuckoo.network.dns_lookup(/play.pampopholf.com/i) or
        androguard.url(/s3.pampopholf.com/i) or cuckoo.network.dns_lookup(/s3.pampopholf.com/i) or
        androguard.url(/play.malictuiar.com/i) or cuckoo.network.dns_lookup(/play.malictuiar.com/i) or
        androguard.url(/s3.malictuiar.com/i) or cuckoo.network.dns_lookup(/s3.malictuiar.com/i) or
        androguard.url(/play.play.tainiesonline.stream/i) or cuckoo.network.dns_lookup(/play.play.tainiesonline.stream/i) or
        androguard.url(/ocean2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/ocean2.authcaptcha.com/i) or
        androguard.url(/rock2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/rock2.authcaptcha.com/i) or
        androguard.url(/stone2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/stone2.authcaptcha.com/i) or
        androguard.url(/sass2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/sass2.authcaptcha.com/i) or
        androguard.url(/sea2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/sea2.authcaptcha.com/i) or
        androguard.url(/play.flowplayer.space/i) or cuckoo.network.dns_lookup(/play.flowplayer.space/i) or
        androguard.url(/play.pc.belicimo.pw/i) or cuckoo.network.dns_lookup(/play.pc.belicimo.pw/i) or
        androguard.url(/play.power.tainiesonline.pw/i) or cuckoo.network.dns_lookup(/play.power.tainiesonline.pw/i) or
        androguard.url(/play.s01.vidtodo.pro/i) or cuckoo.network.dns_lookup(/play.s01.vidtodo.pro/i) or
        androguard.url(/play.cc.gofile.io/i) or cuckoo.network.dns_lookup(/play.cc.gofile.io/i) or
        androguard.url(/wm.yololike.space/i) or cuckoo.network.dns_lookup(/wm.yololike.space/i) or
        androguard.url(/play.mix.kinostuff.com/i) or cuckoo.network.dns_lookup(/play.mix.kinostuff.com/i) or
        androguard.url(/play.on.animeteatr.ru/i) or cuckoo.network.dns_lookup(/play.on.animeteatr.ru/i) or
        androguard.url(/play.mine.gay-hotvideo.net/i) or cuckoo.network.dns_lookup(/play.mine.gay-hotvideo.net/i) or
        androguard.url(/play.www.intellecthosting.net/i) or cuckoo.network.dns_lookup(/play.www.intellecthosting.net/i) or
        androguard.url(/mytestminer.xyz/i) or cuckoo.network.dns_lookup(/mytestminer.xyz/i) or
        androguard.url(/play.vb.wearesaudis.net/i) or cuckoo.network.dns_lookup(/play.vb.wearesaudis.net/i) or
        androguard.url(/flowplayer.space/i) or cuckoo.network.dns_lookup(/flowplayer.space/i) or
        androguard.url(/s2.flowplayer.space/i) or cuckoo.network.dns_lookup(/s2.flowplayer.space/i) or
        androguard.url(/s3.flowplayer.space/i) or cuckoo.network.dns_lookup(/s3.flowplayer.space/i) or
        androguard.url(/thersprens.com/i) or cuckoo.network.dns_lookup(/thersprens.com/i) or
        androguard.url(/s2.thersprens.com/i) or cuckoo.network.dns_lookup(/s2.thersprens.com/i) or
        androguard.url(/s3.thersprens.com/i) or cuckoo.network.dns_lookup(/s3.thersprens.com/i) or
        androguard.url(/play.gramombird.com/i) or cuckoo.network.dns_lookup(/play.gramombird.com/i) or
        androguard.url(/ugmfvqsu.ru/i) or cuckoo.network.dns_lookup(/ugmfvqsu.ru/i) or
        androguard.url(/bsyauqwerd.party/i) or cuckoo.network.dns_lookup(/bsyauqwerd.party/i) or
        androguard.url(/ccvwtdtwyu.trade/i) or cuckoo.network.dns_lookup(/ccvwtdtwyu.trade/i) or
        androguard.url(/baywttgdhe.download/i) or cuckoo.network.dns_lookup(/baywttgdhe.download/i) or
        androguard.url(/pdheuryopd.loan/i) or cuckoo.network.dns_lookup(/pdheuryopd.loan/i) or
        androguard.url(/iaheyftbsn.review/i) or cuckoo.network.dns_lookup(/iaheyftbsn.review/i) or
        androguard.url(/djfhwosjck.bid/i) or cuckoo.network.dns_lookup(/djfhwosjck.bid/i) or
        androguard.url(/najsiejfnc.win/i) or cuckoo.network.dns_lookup(/najsiejfnc.win/i) or
        androguard.url(/zndaowjdnf.stream/i) or cuckoo.network.dns_lookup(/zndaowjdnf.stream/i) or
        androguard.url(/yqaywudifu.date/i) or cuckoo.network.dns_lookup(/yqaywudifu.date/i) or
        androguard.url(/malictuiar.com/i) or cuckoo.network.dns_lookup(/malictuiar.com/i) or
        androguard.url(/proofly.win/i) or cuckoo.network.dns_lookup(/proofly.win/i) or
        androguard.url(/zminer.zaloapp.com/i) or cuckoo.network.dns_lookup(/zminer.zaloapp.com/i) or
        androguard.url(/vkcdnservice.com/i) or cuckoo.network.dns_lookup(/vkcdnservice.com/i) or
        androguard.url(/dexim.space/i) or cuckoo.network.dns_lookup(/dexim.space/i) or
        androguard.url(/acbp0020171456.page.tl/i) or cuckoo.network.dns_lookup(/acbp0020171456.page.tl/i) or
        androguard.url(/vuryua.ru/i) or cuckoo.network.dns_lookup(/vuryua.ru/i) or
        androguard.url(/minexmr.stream/i) or cuckoo.network.dns_lookup(/minexmr.stream/i) or
        androguard.url(/gitgrub.pro/i) or cuckoo.network.dns_lookup(/gitgrub.pro/i) or
        androguard.url(/d8acddffe978b5dfcae6.date/i) or cuckoo.network.dns_lookup(/d8acddffe978b5dfcae6.date/i) or
        androguard.url(/eth-pocket.com/i) or cuckoo.network.dns_lookup(/eth-pocket.com/i) or
        androguard.url(/autologica.ga/i) or cuckoo.network.dns_lookup(/autologica.ga/i) or
        androguard.url(/whysoserius.club/i) or cuckoo.network.dns_lookup(/whysoserius.club/i) or
        androguard.url(/aster18cdn.nl/i) or cuckoo.network.dns_lookup(/aster18cdn.nl/i) or
        androguard.url(/nerohut.com/i) or cuckoo.network.dns_lookup(/nerohut.com/i) or
        androguard.url(/gnrdomimplementation.com/i) or cuckoo.network.dns_lookup(/gnrdomimplementation.com/i) or
        androguard.url(/pon.ewtuyytdf45.com/i) or cuckoo.network.dns_lookup(/pon.ewtuyytdf45.com/i) or
        androguard.url(/hhb123.tk/i) or cuckoo.network.dns_lookup(/hhb123.tk/i) or
        androguard.url(/dzizsih.ru/i) or cuckoo.network.dns_lookup(/dzizsih.ru/i) or
        androguard.url(/nddmcconmqsy.ru/i) or cuckoo.network.dns_lookup(/nddmcconmqsy.ru/i) or
        androguard.url(/silimbompom.com/i) or cuckoo.network.dns_lookup(/silimbompom.com/i) or
        androguard.url(/unrummaged.com/i) or cuckoo.network.dns_lookup(/unrummaged.com/i) or
        androguard.url(/fruitice.realnetwrk.com/i) or cuckoo.network.dns_lookup(/fruitice.realnetwrk.com/i) or
        androguard.url(/synconnector.com/i) or cuckoo.network.dns_lookup(/synconnector.com/i) or
        androguard.url(/toftofcal.com/i) or cuckoo.network.dns_lookup(/toftofcal.com/i) or
        androguard.url(/gasolina.ml/i) or cuckoo.network.dns_lookup(/gasolina.ml/i) or
        androguard.url(/8jd2lfsq.me/i) or cuckoo.network.dns_lookup(/8jd2lfsq.me/i) or
        androguard.url(/afflow.18-plus.net/i) or cuckoo.network.dns_lookup(/afflow.18-plus.net/i) or
        androguard.url(/afminer.com/i) or cuckoo.network.dns_lookup(/afminer.com/i) or
        androguard.url(/aservices.party/i) or cuckoo.network.dns_lookup(/aservices.party/i) or
        androguard.url(/becanium.com/i) or cuckoo.network.dns_lookup(/becanium.com/i) or
        androguard.url(/brominer.com/i) or cuckoo.network.dns_lookup(/brominer.com/i) or
        androguard.url(/cdn-analytics.pl/i) or cuckoo.network.dns_lookup(/cdn-analytics.pl/i) or
        androguard.url(/cdn.static-cnt.bid/i) or cuckoo.network.dns_lookup(/cdn.static-cnt.bid/i) or
        androguard.url(/cloudcdn.gdn/i) or cuckoo.network.dns_lookup(/cloudcdn.gdn/i) or
        androguard.url(/coin-service.com/i) or cuckoo.network.dns_lookup(/coin-service.com/i) or
        androguard.url(/coinpot.co/i) or cuckoo.network.dns_lookup(/coinpot.co/i) or
        androguard.url(/coinrail.io/i) or cuckoo.network.dns_lookup(/coinrail.io/i) or
        androguard.url(/etacontent.com/i) or cuckoo.network.dns_lookup(/etacontent.com/i) or
        androguard.url(/exdynsrv.com/i) or cuckoo.network.dns_lookup(/exdynsrv.com/i) or
        androguard.url(/formulawire.com/i) or cuckoo.network.dns_lookup(/formulawire.com/i) or
        androguard.url(/go.bestmobiworld.com/i) or cuckoo.network.dns_lookup(/go.bestmobiworld.com/i) or
        androguard.url(/goldoffer.online/i) or cuckoo.network.dns_lookup(/goldoffer.online/i) or
        androguard.url(/hallaert.online/i) or cuckoo.network.dns_lookup(/hallaert.online/i) or
        androguard.url(/hashing.win/i) or cuckoo.network.dns_lookup(/hashing.win/i) or
        androguard.url(/igrid.org/i) or cuckoo.network.dns_lookup(/igrid.org/i) or
        androguard.url(/laserveradedomaina.com/i) or cuckoo.network.dns_lookup(/laserveradedomaina.com/i) or
        androguard.url(/machieved.com/i) or cuckoo.network.dns_lookup(/machieved.com/i) or
        androguard.url(/nametraff.com/i) or cuckoo.network.dns_lookup(/nametraff.com/i) or
        androguard.url(/offerreality.com/i) or cuckoo.network.dns_lookup(/offerreality.com/i) or
        androguard.url(/ogrid.org/i) or cuckoo.network.dns_lookup(/ogrid.org/i) or
        androguard.url(/panelsave.com/i) or cuckoo.network.dns_lookup(/panelsave.com/i) or
        androguard.url(/party-vqgdyvoycc.now.sh/i) or cuckoo.network.dns_lookup(/party-vqgdyvoycc.now.sh/i) or
        androguard.url(/pertholin.com/i) or cuckoo.network.dns_lookup(/pertholin.com/i) or
        androguard.url(/premiumstats.xyz/i) or cuckoo.network.dns_lookup(/premiumstats.xyz/i) or
        androguard.url(/serie-vostfr.com/i) or cuckoo.network.dns_lookup(/serie-vostfr.com/i) or
        androguard.url(/salamaleyum.com/i) or cuckoo.network.dns_lookup(/salamaleyum.com/i) or
        androguard.url(/smartoffer.site/i) or cuckoo.network.dns_lookup(/smartoffer.site/i) or
        androguard.url(/stonecalcom.com/i) or cuckoo.network.dns_lookup(/stonecalcom.com/i) or
        androguard.url(/thewhizmarketing.com/i) or cuckoo.network.dns_lookup(/thewhizmarketing.com/i) or
        androguard.url(/thewhizproducts.com/i) or cuckoo.network.dns_lookup(/thewhizproducts.com/i) or
        androguard.url(/thewise.com/i) or cuckoo.network.dns_lookup(/thewise.com/i) or
        androguard.url(/traffic.tc-clicks.com/i) or cuckoo.network.dns_lookup(/traffic.tc-clicks.com/i) or
        androguard.url(/vcfs6ip5h6.bid/i) or cuckoo.network.dns_lookup(/vcfs6ip5h6.bid/i) or
        androguard.url(/web.dle-news.pw/i) or cuckoo.network.dns_lookup(/web.dle-news.pw/i) or
        androguard.url(/webmining.co/i) or cuckoo.network.dns_lookup(/webmining.co/i) or
        androguard.url(/wp-monero-miner.de/i) or cuckoo.network.dns_lookup(/wp-monero-miner.de/i) or
        androguard.url(/wtm.monitoringservice.co/i) or cuckoo.network.dns_lookup(/wtm.monitoringservice.co/i) or
        androguard.url(/xy.nullrefexcep.com/i) or cuckoo.network.dns_lookup(/xy.nullrefexcep.com/i) or
        androguard.url(/yrdrtzmsmt.com/i) or cuckoo.network.dns_lookup(/yrdrtzmsmt.com/i) or
        androguard.url(/wss.rand.com.ru/i) or cuckoo.network.dns_lookup(/wss.rand.com.ru/i) or
        androguard.url(/verifier.live/i) or cuckoo.network.dns_lookup(/verifier.live/i) or
        androguard.url(/jshosting.bid/i) or cuckoo.network.dns_lookup(/jshosting.bid/i) or
        androguard.url(/jshosting.date/i) or cuckoo.network.dns_lookup(/jshosting.date/i) or
        androguard.url(/jshosting.download/i) or cuckoo.network.dns_lookup(/jshosting.download/i) or
        androguard.url(/jshosting.faith/i) or cuckoo.network.dns_lookup(/jshosting.faith/i) or
        androguard.url(/jshosting.loan/i) or cuckoo.network.dns_lookup(/jshosting.loan/i) or
        androguard.url(/jshosting.party/i) or cuckoo.network.dns_lookup(/jshosting.party/i) or
        androguard.url(/jshosting.racing/i) or cuckoo.network.dns_lookup(/jshosting.racing/i) or
        androguard.url(/jshosting.review/i) or cuckoo.network.dns_lookup(/jshosting.review/i) or
        androguard.url(/jshosting.science/i) or cuckoo.network.dns_lookup(/jshosting.science/i) or
        androguard.url(/jshosting.stream/i) or cuckoo.network.dns_lookup(/jshosting.stream/i) or
        androguard.url(/jshosting.trade/i) or cuckoo.network.dns_lookup(/jshosting.trade/i) or
        androguard.url(/jshosting.win/i) or cuckoo.network.dns_lookup(/jshosting.win/i) or
        androguard.url(/freecontent.download/i) or cuckoo.network.dns_lookup(/freecontent.download/i) or
        androguard.url(/freecontent.party/i) or cuckoo.network.dns_lookup(/freecontent.party/i) or
        androguard.url(/freecontent.review/i) or cuckoo.network.dns_lookup(/freecontent.review/i) or
        androguard.url(/freecontent.science/i) or cuckoo.network.dns_lookup(/freecontent.science/i) or
        androguard.url(/freecontent.stream/i) or cuckoo.network.dns_lookup(/freecontent.stream/i) or
        androguard.url(/freecontent.trade/i) or cuckoo.network.dns_lookup(/freecontent.trade/i) or
        androguard.url(/hostingcloud.bid/i) or cuckoo.network.dns_lookup(/hostingcloud.bid/i) or
        androguard.url(/hostingcloud.date/i) or cuckoo.network.dns_lookup(/hostingcloud.date/i) or
        androguard.url(/hostingcloud.faith/i) or cuckoo.network.dns_lookup(/hostingcloud.faith/i) or
        androguard.url(/hostingcloud.loan/i) or cuckoo.network.dns_lookup(/hostingcloud.loan/i) or
        androguard.url(/hostingcloud.party/i) or cuckoo.network.dns_lookup(/hostingcloud.party/i) or
        androguard.url(/hostingcloud.racing/i) or cuckoo.network.dns_lookup(/hostingcloud.racing/i) or
        androguard.url(/hostingcloud.review/i) or cuckoo.network.dns_lookup(/hostingcloud.review/i) or
        androguard.url(/hostingcloud.science/i) or cuckoo.network.dns_lookup(/hostingcloud.science/i) or
        androguard.url(/hostingcloud.stream/i) or cuckoo.network.dns_lookup(/hostingcloud.stream/i) or
        androguard.url(/hostingcloud.trade/i) or cuckoo.network.dns_lookup(/hostingcloud.trade/i) or
        androguard.url(/hostingcloud.win/i) or cuckoo.network.dns_lookup(/hostingcloud.win/i) or
        androguard.url(/minerad.com/i) or cuckoo.network.dns_lookup(/minerad.com/i) or
        androguard.url(/coin-cube.com/i) or cuckoo.network.dns_lookup(/coin-cube.com/i) or
        androguard.url(/coin-services.info/i) or cuckoo.network.dns_lookup(/coin-services.info/i) or
        androguard.url(/service4refresh.info/i) or cuckoo.network.dns_lookup(/service4refresh.info/i) or
        androguard.url(/money-maker-script.info/i) or cuckoo.network.dns_lookup(/money-maker-script.info/i) or
        androguard.url(/money-maker-default.info/i) or cuckoo.network.dns_lookup(/money-maker-default.info/i) or
        androguard.url(/money-maker-default.info/i) or cuckoo.network.dns_lookup(/money-maker-default.info/i) or
        androguard.url(/de-ner-mi-nis4.info/i) or cuckoo.network.dns_lookup(/de-ner-mi-nis4.info/i) or
        androguard.url(/de-nis-ner-mi-5.info/i) or cuckoo.network.dns_lookup(/de-nis-ner-mi-5.info/i) or
        androguard.url(/de-mi-nis-ner2.info/i) or cuckoo.network.dns_lookup(/de-mi-nis-ner2.info/i) or
        androguard.url(/de-mi-nis-ner.info/i) or cuckoo.network.dns_lookup(/de-mi-nis-ner.info/i) or
        androguard.url(/mi-de-ner-nis3.info/i) or cuckoo.network.dns_lookup(/mi-de-ner-nis3.info/i) or
        androguard.url(/s2.soodatmish.com/i) or cuckoo.network.dns_lookup(/s2.soodatmish.com/i) or
        androguard.url(/s2.thersprens.com/i) or cuckoo.network.dns_lookup(/s2.thersprens.com/i) or
        androguard.url(/play.feesocrald.com/i) or cuckoo.network.dns_lookup(/play.feesocrald.com/i) or
        androguard.url(/cdn1.pebx.pl/i) or cuckoo.network.dns_lookup(/cdn1.pebx.pl/i) or
        androguard.url(/play.nexioniect.com/i) or cuckoo.network.dns_lookup(/play.nexioniect.com/i) or
        androguard.url(/play.besstahete.info/i) or cuckoo.network.dns_lookup(/play.besstahete.info/i) or
        androguard.url(/s2.myregeneaf.com/i) or cuckoo.network.dns_lookup(/s2.myregeneaf.com/i) or
        androguard.url(/s3.myregeneaf.com/i) or cuckoo.network.dns_lookup(/s3.myregeneaf.com/i) or
        androguard.url(/reauthenticator.com/i) or cuckoo.network.dns_lookup(/reauthenticator.com/i) or
        androguard.url(/rock.reauthenticator.com/i) or cuckoo.network.dns_lookup(/rock.reauthenticator.com/i) or
        androguard.url(/serv1swork.com/i) or cuckoo.network.dns_lookup(/serv1swork.com/i) or
        androguard.url(/str1kee.com/i) or cuckoo.network.dns_lookup(/str1kee.com/i) or
        androguard.url(/f1tbit.com/i) or cuckoo.network.dns_lookup(/f1tbit.com/i) or
        androguard.url(/g1thub.com/i) or cuckoo.network.dns_lookup(/g1thub.com/i) or
        androguard.url(/swiftmining.win/i) or cuckoo.network.dns_lookup(/swiftmining.win/i) or
        androguard.url(/cashbeet.com/i) or cuckoo.network.dns_lookup(/cashbeet.com/i) or
        androguard.url(/wmtech.website/i) or cuckoo.network.dns_lookup(/wmtech.website/i) or
        androguard.url(/www.notmining.org/i) or cuckoo.network.dns_lookup(/www.notmining.org/i) or
        androguard.url(/coinminingonline.com/i) or cuckoo.network.dns_lookup(/coinminingonline.com/i) or
        androguard.url(/alflying.bid/i) or cuckoo.network.dns_lookup(/alflying.bid/i) or
        androguard.url(/alflying.date/i) or cuckoo.network.dns_lookup(/alflying.date/i) or
        androguard.url(/alflying.win/i) or cuckoo.network.dns_lookup(/alflying.win/i) or
        androguard.url(/anybest.host/i) or cuckoo.network.dns_lookup(/anybest.host/i) or
        androguard.url(/anybest.pw/i) or cuckoo.network.dns_lookup(/anybest.pw/i) or
        androguard.url(/anybest.site/i) or cuckoo.network.dns_lookup(/anybest.site/i) or
        androguard.url(/anybest.space/i) or cuckoo.network.dns_lookup(/anybest.space/i) or
        androguard.url(/dubester.pw/i) or cuckoo.network.dns_lookup(/dubester.pw/i) or
        androguard.url(/dubester.site/i) or cuckoo.network.dns_lookup(/dubester.site/i) or
        androguard.url(/dubester.space/i) or cuckoo.network.dns_lookup(/dubester.space/i) or
        androguard.url(/flightsy.bid/i) or cuckoo.network.dns_lookup(/flightsy.bid/i) or
        androguard.url(/flightsy.date/i) or cuckoo.network.dns_lookup(/flightsy.date/i) or
        androguard.url(/flightsy.win/i) or cuckoo.network.dns_lookup(/flightsy.win/i) or
        androguard.url(/flighty.win/i) or cuckoo.network.dns_lookup(/flighty.win/i) or
        androguard.url(/flightzy.bid/i) or cuckoo.network.dns_lookup(/flightzy.bid/i) or
        androguard.url(/flightzy.date/i) or cuckoo.network.dns_lookup(/flightzy.date/i) or
        androguard.url(/flightzy.win/i) or cuckoo.network.dns_lookup(/flightzy.win/i) or
        androguard.url(/gettate.date/i) or cuckoo.network.dns_lookup(/gettate.date/i) or
        androguard.url(/gettate.faith/i) or cuckoo.network.dns_lookup(/gettate.faith/i) or
        androguard.url(/gettate.racing/i) or cuckoo.network.dns_lookup(/gettate.racing/i) or
        androguard.url(/mighbest.host/i) or cuckoo.network.dns_lookup(/mighbest.host/i) or
        androguard.url(/mighbest.pw/i) or cuckoo.network.dns_lookup(/mighbest.pw/i) or
        androguard.url(/mighbest.site/i) or cuckoo.network.dns_lookup(/mighbest.site/i) or
        androguard.url(/zymerget.bid/i) or cuckoo.network.dns_lookup(/zymerget.bid/i) or
        androguard.url(/zymerget.date/i) or cuckoo.network.dns_lookup(/zymerget.date/i) or
        androguard.url(/zymerget.faith/i) or cuckoo.network.dns_lookup(/zymerget.faith/i) or
        androguard.url(/zymerget.party/i) or cuckoo.network.dns_lookup(/zymerget.party/i) or
        androguard.url(/zymerget.stream/i) or cuckoo.network.dns_lookup(/zymerget.stream/i) or
        androguard.url(/zymerget.win/i) or cuckoo.network.dns_lookup(/zymerget.win/i) or
        androguard.url(/statdynamic.com/i) or cuckoo.network.dns_lookup(/statdynamic.com/i) or
        androguard.url(/alpha.nimiqpool.com/i) or cuckoo.network.dns_lookup(/alpha.nimiqpool.com/i) or
        androguard.url(/api.miner.beeppool.org/i) or cuckoo.network.dns_lookup(/api.miner.beeppool.org/i) or
        androguard.url(/beatingbytes.com/i) or cuckoo.network.dns_lookup(/beatingbytes.com/i) or
        androguard.url(/besocial.online/i) or cuckoo.network.dns_lookup(/besocial.online/i) or
        androguard.url(/beta.nimiqpool.com/i) or cuckoo.network.dns_lookup(/beta.nimiqpool.com/i) or
        androguard.url(/bulls.nimiqpool.com/i) or cuckoo.network.dns_lookup(/bulls.nimiqpool.com/i) or
        androguard.url(/de1.eu.nimiqpool.com/i) or cuckoo.network.dns_lookup(/de1.eu.nimiqpool.com/i) or
        androguard.url(/ethmedialab.info/i) or cuckoo.network.dns_lookup(/ethmedialab.info/i) or
        androguard.url(/feilding.nimiqpool.com/i) or cuckoo.network.dns_lookup(/feilding.nimiqpool.com/i) or
        androguard.url(/foxton.nimiqpool.com/i) or cuckoo.network.dns_lookup(/foxton.nimiqpool.com/i) or
        androguard.url(/ganymed.beeppool.org/i) or cuckoo.network.dns_lookup(/ganymed.beeppool.org/i) or
        androguard.url(/himatangi.nimiqpool.com/i) or cuckoo.network.dns_lookup(/himatangi.nimiqpool.com/i) or
        androguard.url(/levin.nimiqpool.com/i) or cuckoo.network.dns_lookup(/levin.nimiqpool.com/i) or
        androguard.url(/mine.terorie.com/i) or cuckoo.network.dns_lookup(/mine.terorie.com/i) or
        androguard.url(/miner-1.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-1.team.nimiq.agency/i) or
        androguard.url(/miner-10.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-10.team.nimiq.agency/i) or
        androguard.url(/miner-11.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-11.team.nimiq.agency/i) or
        androguard.url(/miner-12.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-12.team.nimiq.agency/i) or
        androguard.url(/miner-13.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-13.team.nimiq.agency/i) or
        androguard.url(/miner-14.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-14.team.nimiq.agency/i) or
        androguard.url(/miner-15.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-15.team.nimiq.agency/i) or
        androguard.url(/miner-16.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-16.team.nimiq.agency/i) or
        androguard.url(/miner-17.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-17.team.nimiq.agency/i) or
        androguard.url(/miner-18.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-18.team.nimiq.agency/i) or
        androguard.url(/miner-19.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-19.team.nimiq.agency/i) or
        androguard.url(/miner-2.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-2.team.nimiq.agency/i) or
        androguard.url(/miner-3.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-3.team.nimiq.agency/i) or
        androguard.url(/miner-4.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-4.team.nimiq.agency/i) or
        androguard.url(/miner-5.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-5.team.nimiq.agency/i) or
        androguard.url(/miner-6.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-6.team.nimiq.agency/i) or
        androguard.url(/miner-7.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-7.team.nimiq.agency/i) or
        androguard.url(/miner-8.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-8.team.nimiq.agency/i) or
        androguard.url(/miner-9.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-9.team.nimiq.agency/i) or
        androguard.url(/miner-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-1.inf.nimiq.network/i) or
        androguard.url(/miner-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-2.inf.nimiq.network/i) or
        androguard.url(/miner-deu-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-3.inf.nimiq.network/i) or
        androguard.url(/miner-deu-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-4.inf.nimiq.network/i) or
        androguard.url(/miner-deu-5.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-5.inf.nimiq.network/i) or
        androguard.url(/miner-deu-6.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-6.inf.nimiq.network/i) or
        androguard.url(/miner-deu-7.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-7.inf.nimiq.network/i) or
        androguard.url(/miner-deu-8.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-8.inf.nimiq.network/i) or
        androguard.url(/miner.beeppool.org/i) or cuckoo.network.dns_lookup(/miner.beeppool.org/i) or
        androguard.url(/miner.nimiq.com/i) or cuckoo.network.dns_lookup(/miner.nimiq.com/i) or
        androguard.url(/mon-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-deu-1.inf.nimiq.network/i) or
        androguard.url(/mon-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-deu-2.inf.nimiq.network/i) or
        androguard.url(/mon-deu-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-deu-3.inf.nimiq.network/i) or
        androguard.url(/mon-fra-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-fra-1.inf.nimiq.network/i) or
        androguard.url(/mon-fra-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-fra-2.inf.nimiq.network/i) or
        androguard.url(/mon-gbr-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-gbr-1.inf.nimiq.network/i) or
        androguard.url(/nimiq.terorie.com/i) or cuckoo.network.dns_lookup(/nimiq.terorie.com/i) or
        androguard.url(/nimiqpool.com/i) or cuckoo.network.dns_lookup(/nimiqpool.com/i) or
        androguard.url(/nimiqtest.ml/i) or cuckoo.network.dns_lookup(/nimiqtest.ml/i) or
        androguard.url(/ninaning.com/i) or cuckoo.network.dns_lookup(/ninaning.com/i) or
        androguard.url(/node.alpha.nimiqpool.com/i) or cuckoo.network.dns_lookup(/node.alpha.nimiqpool.com/i) or
        androguard.url(/node.nimiqpool.com/i) or cuckoo.network.dns_lookup(/node.nimiqpool.com/i) or
        androguard.url(/nodeb.nimiqpool.com/i) or cuckoo.network.dns_lookup(/nodeb.nimiqpool.com/i) or
        androguard.url(/nodeone.nimiqpool.com/i) or cuckoo.network.dns_lookup(/nodeone.nimiqpool.com/i) or
        androguard.url(/proxy-can-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-can-1.inf.nimiq.network/i) or
        androguard.url(/proxy-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-deu-1.inf.nimiq.network/i) or
        androguard.url(/proxy-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-deu-2.inf.nimiq.network/i) or
        androguard.url(/proxy-fra-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-fra-1.inf.nimiq.network/i) or
        androguard.url(/proxy-fra-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-fra-2.inf.nimiq.network/i) or
        androguard.url(/proxy-fra-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-fra-3.inf.nimiq.network/i) or
        androguard.url(/proxy-gbr-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-gbr-1.inf.nimiq.network/i) or
        androguard.url(/proxy-gbr-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-gbr-2.inf.nimiq.network/i) or
        androguard.url(/proxy-pol-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-pol-1.inf.nimiq.network/i) or
        androguard.url(/proxy-pol-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-pol-2.inf.nimiq.network/i) or
        androguard.url(/script.nimiqpool.com/i) or cuckoo.network.dns_lookup(/script.nimiqpool.com/i) or
        androguard.url(/seed-1.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-1.nimiq-network.com/i) or
        androguard.url(/seed-1.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-1.nimiq.com/i) or
        androguard.url(/seed-1.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-1.nimiq.network/i) or
        androguard.url(/seed-10.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-10.nimiq-network.com/i) or
        androguard.url(/seed-10.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-10.nimiq.com/i) or
        androguard.url(/seed-10.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-10.nimiq.network/i) or
        androguard.url(/seed-11.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-11.nimiq-network.com/i) or
        androguard.url(/seed-11.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-11.nimiq.com/i) or
        androguard.url(/seed-11.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-11.nimiq.network/i) or
        androguard.url(/seed-12.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-12.nimiq-network.com/i) or
        androguard.url(/seed-12.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-12.nimiq.com/i) or
        androguard.url(/seed-12.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-12.nimiq.network/i) or
        androguard.url(/seed-13.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-13.nimiq-network.com/i) or
        androguard.url(/seed-13.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-13.nimiq.com/i) or
        androguard.url(/seed-13.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-13.nimiq.network/i) or
        androguard.url(/seed-14.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-14.nimiq-network.com/i) or
        androguard.url(/seed-14.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-14.nimiq.com/i) or
        androguard.url(/seed-14.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-14.nimiq.network/i) or
        androguard.url(/seed-15.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-15.nimiq-network.com/i) or
        androguard.url(/seed-15.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-15.nimiq.com/i) or
        androguard.url(/seed-15.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-15.nimiq.network/i) or
        androguard.url(/seed-16.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-16.nimiq-network.com/i) or
        androguard.url(/seed-16.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-16.nimiq.com/i) or
        androguard.url(/seed-16.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-16.nimiq.network/i) or
        androguard.url(/seed-17.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-17.nimiq-network.com/i) or
        androguard.url(/seed-17.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-17.nimiq.com/i) or
        androguard.url(/seed-17.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-17.nimiq.network/i) or
        androguard.url(/seed-18.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-18.nimiq-network.com/i) or
        androguard.url(/seed-18.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-18.nimiq.com/i) or
        androguard.url(/seed-18.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-18.nimiq.network/i) or
        androguard.url(/seed-19.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-19.nimiq-network.com/i) or
        androguard.url(/seed-19.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-19.nimiq.com/i) or
        androguard.url(/seed-19.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-19.nimiq.network/i) or
        androguard.url(/seed-2.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-2.nimiq-network.com/i) or
        androguard.url(/seed-2.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-2.nimiq.com/i) or
        androguard.url(/seed-2.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-2.nimiq.network/i) or
        androguard.url(/seed-20.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-20.nimiq-network.com/i) or
        androguard.url(/seed-20.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-20.nimiq.com/i) or
        androguard.url(/seed-20.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-20.nimiq.network/i) or
        androguard.url(/seed-3.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-3.nimiq-network.com/i) or
        androguard.url(/seed-3.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-3.nimiq.com/i) or
        androguard.url(/seed-3.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-3.nimiq.network/i) or
        androguard.url(/seed-4.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-4.nimiq-network.com/i) or
        androguard.url(/seed-4.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-4.nimiq.com/i) or
        androguard.url(/seed-4.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-4.nimiq.network/i) or
        androguard.url(/seed-5.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-5.nimiq-network.com/i) or
        androguard.url(/seed-5.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-5.nimiq.com/i) or
        androguard.url(/seed-5.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-5.nimiq.network/i) or
        androguard.url(/seed-6.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-6.nimiq-network.com/i) or
        androguard.url(/seed-6.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-6.nimiq.com/i) or
        androguard.url(/seed-6.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-6.nimiq.network/i) or
        androguard.url(/seed-7.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-7.nimiq-network.com/i) or
        androguard.url(/seed-7.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-7.nimiq.com/i) or
        androguard.url(/seed-7.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-7.nimiq.network/i) or
        androguard.url(/seed-8.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-8.nimiq-network.com/i) or
        androguard.url(/seed-8.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-8.nimiq.com/i) or
        androguard.url(/seed-8.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-8.nimiq.network/i) or
        androguard.url(/seed-9.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-9.nimiq-network.com/i) or
        androguard.url(/seed-9.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-9.nimiq.com/i) or
        androguard.url(/seed-9.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-9.nimiq.network/i) or
        androguard.url(/seed-can-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-can-1.inf.nimiq.network/i) or
        androguard.url(/seed-can-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-can-2.inf.nimiq.network/i) or
        androguard.url(/seed-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-1.inf.nimiq.network/i) or
        androguard.url(/seed-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-2.inf.nimiq.network/i) or
        androguard.url(/seed-deu-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-3.inf.nimiq.network/i) or
        androguard.url(/seed-deu-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-4.inf.nimiq.network/i) or
        androguard.url(/seed-fra-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-1.inf.nimiq.network/i) or
        androguard.url(/seed-fra-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-2.inf.nimiq.network/i) or
        androguard.url(/seed-fra-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-3.inf.nimiq.network/i) or
        androguard.url(/seed-fra-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-4.inf.nimiq.network/i) or
        androguard.url(/seed-fra-5.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-5.inf.nimiq.network/i) or
        androguard.url(/seed-fra-6.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-6.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-1.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-2.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-3.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-4.inf.nimiq.network/i) or
        androguard.url(/seed-pol-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-1.inf.nimiq.network/i) or
        androguard.url(/seed-pol-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-2.inf.nimiq.network/i) or
        androguard.url(/seed-pol-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-3.inf.nimiq.network/i) or
        androguard.url(/seed-pol-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-4.inf.nimiq.network/i) or
        androguard.url(/seed.nimiqpool.com/i) or cuckoo.network.dns_lookup(/seed.nimiqpool.com/i) or
        androguard.url(/seed1.sushipool.com/i) or cuckoo.network.dns_lookup(/seed1.sushipool.com/i) or
        androguard.url(/shannon.nimiqpool.com/i) or cuckoo.network.dns_lookup(/shannon.nimiqpool.com/i) or
        androguard.url(/sunnimiq.cf/i) or cuckoo.network.dns_lookup(/sunnimiq.cf/i) or
        androguard.url(/sunnimiq1.cf/i) or cuckoo.network.dns_lookup(/sunnimiq1.cf/i) or
        androguard.url(/sunnimiq2.cf/i) or cuckoo.network.dns_lookup(/sunnimiq2.cf/i) or
        androguard.url(/sunnimiq3.cf/i) or cuckoo.network.dns_lookup(/sunnimiq3.cf/i) or
        androguard.url(/sunnimiq4.cf/i) or cuckoo.network.dns_lookup(/sunnimiq4.cf/i) or
        androguard.url(/sunnimiq5.cf/i) or cuckoo.network.dns_lookup(/sunnimiq5.cf/i) or
        androguard.url(/sunnimiq6.cf/i) or cuckoo.network.dns_lookup(/sunnimiq6.cf/i) or
        androguard.url(/tokomaru.nimiqpool.com/i) or cuckoo.network.dns_lookup(/tokomaru.nimiqpool.com/i) or
        androguard.url(/whanganui.nimiqpool.com/i) or cuckoo.network.dns_lookup(/whanganui.nimiqpool.com/i) or
        androguard.url(/www.besocial.online/i) or cuckoo.network.dns_lookup(/www.besocial.online/i) or
        androguard.url(/nimiq.com/i) or cuckoo.network.dns_lookup(/nimiq.com/i) or
        androguard.url(/miner.nimiq.com/i) or cuckoo.network.dns_lookup(/miner.nimiq.com/i) or
        androguard.url(/cdn.nimiq.com/i) or cuckoo.network.dns_lookup(/cdn.nimiq.com/i) or
        androguard.url(/jscoinminer.com/i) or cuckoo.network.dns_lookup(/jscoinminer.com/i) or
        androguard.url(/www.jscoinminer.com/i) or cuckoo.network.dns_lookup(/www.jscoinminer.com/i) or
        androguard.url(/azvjudwr.info/i) or cuckoo.network.dns_lookup(/azvjudwr.info/i) or
        androguard.url(/jroqvbvw.info/i) or cuckoo.network.dns_lookup(/jroqvbvw.info/i) or
        androguard.url(/jyhfuqoh.info/i) or cuckoo.network.dns_lookup(/jyhfuqoh.info/i) or
        androguard.url(/kdowqlpt.info/i) or cuckoo.network.dns_lookup(/kdowqlpt.info/i) or
        androguard.url(/xbasfbno.info/i) or cuckoo.network.dns_lookup(/xbasfbno.info/i) or
        androguard.url(/1beb2a44.space/i) or cuckoo.network.dns_lookup(/1beb2a44.space/i) or
        androguard.url(/300ca0d0.space/i) or cuckoo.network.dns_lookup(/300ca0d0.space/i) or
        androguard.url(/310ca263.space/i) or cuckoo.network.dns_lookup(/310ca263.space/i) or
        androguard.url(/320ca3f6.space/i) or cuckoo.network.dns_lookup(/320ca3f6.space/i) or
        androguard.url(/330ca589.space/i) or cuckoo.network.dns_lookup(/330ca589.space/i) or
        androguard.url(/340ca71c.space/i) or cuckoo.network.dns_lookup(/340ca71c.space/i) or
        androguard.url(/360caa42.space/i) or cuckoo.network.dns_lookup(/360caa42.space/i) or
        androguard.url(/370cabd5.space/i) or cuckoo.network.dns_lookup(/370cabd5.space/i) or
        androguard.url(/3c0cb3b4.space/i) or cuckoo.network.dns_lookup(/3c0cb3b4.space/i) or
        androguard.url(/3d0cb547.space/i) or cuckoo.network.dns_lookup(/3d0cb547.space/i) or
        (any of ($id*)) or
        (any of ($link*)) or
        (any of ($js*)) or 
        (any of ($lib*)) or
        (any of ($api*)) or
        //(any of ($misc*)) or
        (false)) //just a dummy string	
}
