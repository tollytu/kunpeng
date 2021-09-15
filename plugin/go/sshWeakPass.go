package goplugin

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/opensec-cn/kunpeng/plugin"
	"golang.org/x/crypto/ssh"
)

func sshWeak(user string, pass string, netloc string) error {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Duration(10) * time.Second,
	}

	client, err := ssh.Dial("tcp", netloc, config)

	if err != nil {
		defer client.Close()
		return nil
	}
	fmt.Sprintf("connect error")
	return err
}

func sshLogin(ip, username, password string) (bool, error) {
	success := false
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         3 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", ip, config)
	if err == nil {
		defer client.Close()
		success = true
		//session, err := client.NewSession()
		//errRet := session.Run("echo 飞雪无情")
		//if err == nil && errRet == nil {
		//	defer session.Close()
		//
		//}
	} else {
		fmt.Println("connect error")
	}
	return success, err
}

type sshWeakPass struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("ssh", &sshWeakPass{})
}
func (d *sshWeakPass) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "SSH 弱口令",
		Remarks: "直接导致服务器被入侵控制。",
		Level:   0,
		Type:    "WEAKPWD",
		Author:  "Tolly",
		References: plugin.References{
			KPID: "KP-0001",
		},
	}
	return d.info
}
func (d *sshWeakPass) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *sshWeakPass) Check(netloc string, meta plugin.TaskMeta) (b bool) {
	if strings.IndexAny(netloc, "http") == 0 {
		return
	}
	userList := []string{
		"root", "vmuser", "user", "admin", "test",
	}
	for _, user := range userList {
		for _, pass := range meta.PassList {
			_, err := sshLogin(netloc, user, pass)
			//client = ct
			if err == nil {
				result := d.info
				result.Request = fmt.Sprintf("ssh://%s:%s@%s", user, pass, netloc)
				result.Remarks = fmt.Sprintf("弱口令：%s,%s,%s", user, pass, result.Remarks)
				d.result = append(d.result, result)
				b = true
				break
			} else if strings.Contains(err.Error(), "none password") == false {
				return b
			}
		}
	}
	return b
}
