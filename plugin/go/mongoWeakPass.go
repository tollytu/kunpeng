package goplugin

import (
	"fmt"
	"github.com/opensec-cn/kunpeng/plugin"
	"gopkg.in/mgo.v2"
	"time"
)

func MongoAuth(ip string, username string, password string) (result bool, err error) {
	session, err := mgo.DialWithTimeout("mongodb://"+username+":"+password+"@"+ip+"/"+"admin", time.Second*3)
	if err == nil {
		tb, _ := session.DatabaseNames()
		if len(tb) > 0 {
			defer session.Close()
			result = true
		}
	}
	return result, err
}

func MongoUnAuth(ip string) (result bool, err error) {
	session, err := mgo.Dial(ip)
	if err == nil {
		tb, _ := session.DatabaseNames()
		if len(tb) > 0 {
			defer session.Close()
			result = true
		}
	}
	return result, err
}

type mongoWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("mongodb", &mongoWeakPass{})
}
func (d *mongoWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "MongoDB 未授权访问/弱口令",
		Remarks: "导致数据库敏感信息泄露，严重可导致服务器直接被入侵控制。",
		Level:   1,
		Type:    "WEAKPWD",
		Author:  "Tolly",
		References: plugin.References{
			KPID: "KP-0007",
		},
	}
	return d.info
}
func (d *mongoWeakPass) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *mongoWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	userList := []string{
		"admin",
	}
	res, err := MongoUnAuth(netloc)
	if err == nil && res {
		result := d.info
		result.Request = fmt.Sprintf("mgo://%s/admin", netloc)
		result.Remarks = "未授权访问," + result.Remarks
		d.result = append(d.result, result)
		return res
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			res, err := MongoAuth(netloc, user, pass)
			if err == nil && res {
				result := d.info
				result.Request = fmt.Sprintf("mgo://%s:%s@%s/admin", user, pass, netloc)
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				b = res
				break
			}
		}
	}
	return b
}
