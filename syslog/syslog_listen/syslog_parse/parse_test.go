package syslog_prase

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
)

func TestRegexp2(t *testing.T) {
	str := `39.144.81.88|beacon.sina.com.cn.|20210324172228|111.13.134.212;39.156.6.183|0|2|||117.131.225.231|0
111.33.215.94|minner.jr.jd.com.|20210324172228|172.23.68.200|0|1|||117.131.225.231|0
223.104.228.93|as.aw.mt.mob.com.|20210324172228|101.69.180.220|0|1|||117.131.225.231|0
117.136.55.116|android.clients.google.com.|20210324172228|172.217.160.78;172.217.160.110;172.217.24.14|0|1|android.l.google.com.||117.131.225.231|0
111.33.236.228|5.courier-push-apple.com.akadns.net.|20210324172228||0|28|apac-china-courier-4.push-apple.com.akadns.net.||117.131.225.231|0
223.104.7.166|play-lh.googleusercontent.com.|20210324172228||0|28|||117.131.225.231|0
111.32.112.150|alimov2.a.yximgs.com.|20210324172228|120.220.77.218;120.220.77.223;120.220.77.221;120.220.77.222|0|1|alimov2.a.yximgs.com.w.alikunlun.net.||117.131.225.231|0
111.32.88.98|cdn.ark.qq.com.|20210324172228|183.201.241.36;120.221.245.104;120.221.227.216|0|1|cdn.ark.qq.com.cloud.tc.qq.com.;other.sched.ssdv6.tdnsv6.com.||117.131.225.231|0
117.136.54.36|metrics1.data.hicloud.com.|20210324172228|49.4.44.244;118.194.33.204|0|1|||117.131.225.231|0
223.104.227.165|img-2.pddpic.com.|20210324172228||0|28|img-2.pddpic.com.a.bdydns.com.;opencdnpddpic2.jomodns.com.|2409:8C04:1001:B::6F3F:4229;2409:8C04:1002:2::6F3F:3C29;2409:8C04:1003:10C::6F3F:3B29|117.131.225.231|0
111.33.230.160|x-a.adanxing.com.|20210324172228||0|28|||117.131.225.231|0
117.136.1.146|oth.eve.mdt.qq.com.|20210324172228|211.136.109.79;211.136.109.31|0|1|ins-gk5vby51.ias.tencent-cloud.net.||117.131.225.231|0
111.32.118.14|pull-hls-f1.douyincdn.com.|20210324172228|111.31.16.18;111.31.16.19|0|1|pull-hls-f1.douyincdn.com.wsdvs.com.||117.131.225.231|0
111.30.195.33|contentcenter-drcn.dbankcdn.com.|20210324172228|111.31.12.178;111.32.146.235|0|1|contentcenter-drcn-dbankcdn-com-global.staticcdn.dbankedge.net.;contentcenter-drcn.dbankcdn.com.c.cdnhwc1.com.;hcdnw101.gslb.c.cdnhwc2.com.||117.131.225.231|0
111.32.116.75|store.hispace.hicloud.com.|20210324172228|117.78.58.99;49.4.18.123;49.4.44.164;121.36.117.27|0|1|store1.hispace.hicloud.com.||117.131.225.231|0
223.104.228.157|pull-flv-l6.douyincdn.com.|20210324172228||0|28|pull-flv-l6.douyincdn.com.hdlvcloud.ks-cdn.com.;s6110-ml.gslb.ksyuncdn.com.;s6110-ml-goldenkip.gslb.goldenkip.com.||117.131.225.231|0
111.30.201.131|irs01.com.|20210324172228||0|28|||117.131.225.231|0
117.136.55.31|bd-p2p.pull.yximgs.com.|20210324172228|111.32.163.41|0|1|bd-p2p.pull.yximgs.com.a.bcelive.com.;bceksp2p.jomodns.com.||117.131.225.231|0
223.104.227.149|locahost.|20210324172228||3|1|||117.131.225.231|0
111.30.217.167|adash.man.aliyuncs.com.|20210324172228|106.11.248.71|0|1|sh.wagbridge.aliyun-inc.com.;sh.wagbridge.aliyun-inc.com.gds.alibabadns.com.||117.131.225.231|0`

	// 使用命名分组，显得更清晰
	//re := regexp.MustCompile(`(?P<name>[a-zA-Z]+)`)
	re := regexp.MustCompile(`(?P<client_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|(?P<query_name>.*?)\|(?P<timestamp>.*?)\|(?P<result>.*?)\|(?P<query_class>.*?)\|(?P<query_type>.*?)\|`)
	match := re.FindStringSubmatch(str)

	groupNames := re.SubexpNames()

	fmt.Printf("%v, %v, %d, %d\n", match, groupNames, len(match), len(groupNames))

	result := make(map[string]string)

	// 转换为map
	for i, name := range groupNames {
		if i != 0 && name != "" { // 第一个分组为空（也就是整个匹配）
			result[name] = match[i]
		}
	}
	//
	prettyResult, _ := json.MarshalIndent(result, "", "  ")
	//
	fmt.Printf("%s\n", prettyResult)
}

func TestRegexp3(t *testing.T) {

	inputs := []string{
		"(3)d1v(7)ton-wei(3)com(0)",
		"(3)ecs(6)off2ce(14)trafficmanager(3)net(0)",
		"(12)pull-flv-l29(9)douyincdn(3)com(6)ucloud(3)com(2)cn(0)",
	}

	for _, input := range inputs {
		transformed := ParseDomainType1(input)
		fmt.Println(transformed)
	}

}
