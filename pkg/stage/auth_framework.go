package stage

import (
	"bufio"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ssh"
)

type AuthConfig struct {
	Users     []string
	UserDict  map[string][]string
	Passwords []string
	UpPairs   []UserPass
	Retry     int
	Timeout   time.Duration
	MaxTries  int
}

type UserPass struct {
	User string
	Pass string
}

type AuthFrameworkPlugin struct {
	cfg AuthConfig
}

func NewAuthFrameworkPlugin(cfg AuthConfig) *AuthFrameworkPlugin {
	if cfg.Retry <= 0 {
		cfg.Retry = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.MaxTries <= 0 {
		cfg.MaxTries = 24
	}
	return &AuthFrameworkPlugin{cfg: cfg}
}

func (p *AuthFrameworkPlugin) Name() string { return "auth-framework-v1" }
func (p *AuthFrameworkPlugin) Type() PluginType {
	return PluginTypeAuth
}

func (p *AuthFrameworkPlugin) Supports(ctx PluginContext) bool {
	return resolveServiceName(ctx.Service) != ""
}

func (p *AuthFrameworkPlugin) Execute(ctx PluginContext) []AuthEvent {
	service := resolveServiceName(ctx.Service)
	if service == "" {
		return nil
	}

	switch service {
	case "redis":
		return p.tryRedis(ctx.Target.Host, ctx.Service.Port)
	case "ftp":
		return p.tryFTP(ctx.Target.Host, ctx.Service.Port)
	case "mysql":
		return p.tryMySQL(ctx.Target.Host, ctx.Service.Port)
	case "postgresql":
		return p.tryPostgreSQL(ctx.Target.Host, ctx.Service.Port)
	case "ssh":
		return p.trySSH(ctx.Target.Host, ctx.Service.Port)
	default:
		return nil
	}
}

func canonicalServiceName(types []string) string {
	for _, t := range types {
		v := strings.ToLower(strings.TrimSpace(t))
		switch v {
		case "ssh", "redis", "mysql", "postgresql", "ftp":
			return v
		case "postgres":
			return "postgresql"
		}
	}
	return ""
}

func resolveServiceName(s ServiceInfo) string {
	if v := canonicalServiceName(s.Types); v != "" {
		return v
	}
	switch s.Port {
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	default:
		return ""
	}
}

func (p *AuthFrameworkPlugin) tryRedis(host string, port int) []AuthEvent {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, p.cfg.Timeout)
	if err != nil {
		return []AuthEvent{newAuthEvent("redis", "connect_failed", "connect_error", err.Error(), time.Since(start))}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.cfg.Timeout))

	if _, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return []AuthEvent{newAuthEvent("redis", "error", "io_error", err.Error(), time.Since(start))}
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return []AuthEvent{newAuthEvent("redis", "error", "io_error", err.Error(), time.Since(start))}
	}
	resp := string(buf[:n])
	if strings.Contains(resp, "+PONG") {
		return []AuthEvent{newAuthEvent("redis", "success", "", "unauthenticated access", time.Since(start))}
	}

	candidates := p.credentialCandidates("redis")
	for _, c := range candidates {
		if ok, ev := p.redisAuth(addr, c); ok {
			return []AuthEvent{{
				Service:    "redis",
				Username:   c.User,
				Password:   c.Pass,
				Result:     "success",
				Evidence:   ev,
				DurationMS: time.Since(start).Milliseconds(),
			}}
		}
	}
	return []AuthEvent{newAuthEvent("redis", "auth_failed", "auth_denied", "no credential matched", time.Since(start))}
}

func (p *AuthFrameworkPlugin) redisAuth(addr string, cred UserPass) (bool, string) {
	for i := 0; i < p.cfg.Retry; i++ {
		conn, err := net.DialTimeout("tcp", addr, p.cfg.Timeout)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(p.cfg.Timeout))
		var payload string
		if strings.TrimSpace(cred.User) == "" {
			payload = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(cred.Pass), cred.Pass)
		} else {
			payload = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(cred.User), cred.User, len(cred.Pass), cred.Pass)
		}
		_, _ = conn.Write([]byte(payload))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err != nil {
			continue
		}
		resp := string(buf[:n])
		if strings.Contains(resp, "+OK") {
			return true, "AUTH accepted"
		}
	}
	return false, ""
}

func (p *AuthFrameworkPlugin) tryFTP(host string, port int) []AuthEvent {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", host, port)
	candidates := p.credentialCandidates("ftp")
	if len(candidates) == 0 {
		candidates = []UserPass{{User: "anonymous", Pass: "anonymous@"}}
	}

	for _, c := range candidates {
		ok, ev := p.ftpAuth(addr, c)
		if ok {
			return []AuthEvent{{
				Service:    "ftp",
				Username:   c.User,
				Password:   c.Pass,
				Result:     "success",
				Evidence:   ev,
				DurationMS: time.Since(start).Milliseconds(),
			}}
		}
	}
	return []AuthEvent{newAuthEvent("ftp", "auth_failed", "auth_denied", "no credential matched", time.Since(start))}
}

func (p *AuthFrameworkPlugin) tryMySQL(host string, port int) []AuthEvent {
	start := time.Now()
	candidates := p.credentialCandidates("mysql")
	if len(candidates) == 0 {
		return []AuthEvent{newAuthEvent("mysql", "auth_failed", "config_error", "empty credential candidates", time.Since(start))}
	}
	for _, c := range candidates {
		ok, ev := p.mysqlAuth(host, port, c)
		if ok {
			return []AuthEvent{{
				Service:    "mysql",
				Username:   c.User,
				Password:   c.Pass,
				Result:     "success",
				Evidence:   ev,
				DurationMS: time.Since(start).Milliseconds(),
			}}
		}
	}
	return []AuthEvent{newAuthEvent("mysql", "auth_failed", "auth_denied", "no credential matched", time.Since(start))}
}

func (p *AuthFrameworkPlugin) mysqlAuth(host string, port int, cred UserPass) (bool, string) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/mysql?timeout=%s&readTimeout=%s&writeTimeout=%s",
		cred.User, cred.Pass, host, port, p.cfg.Timeout, p.cfg.Timeout, p.cfg.Timeout)
	for i := 0; i < p.cfg.Retry; i++ {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			continue
		}
		db.SetConnMaxLifetime(p.cfg.Timeout)
		db.SetMaxIdleConns(0)
		db.SetMaxOpenConns(1)
		err = db.Ping()
		_ = db.Close()
		if err == nil {
			return true, "MySQL authentication succeeded"
		}
	}
	return false, ""
}

func (p *AuthFrameworkPlugin) tryPostgreSQL(host string, port int) []AuthEvent {
	start := time.Now()
	candidates := p.credentialCandidates("postgresql")
	if len(candidates) == 0 {
		return []AuthEvent{newAuthEvent("postgresql", "auth_failed", "config_error", "empty credential candidates", time.Since(start))}
	}
	for _, c := range candidates {
		ok, ev := p.postgresAuth(host, port, c)
		if ok {
			return []AuthEvent{{
				Service:    "postgresql",
				Username:   c.User,
				Password:   c.Pass,
				Result:     "success",
				Evidence:   ev,
				DurationMS: time.Since(start).Milliseconds(),
			}}
		}
	}
	return []AuthEvent{newAuthEvent("postgresql", "auth_failed", "auth_denied", "no credential matched", time.Since(start))}
}

func (p *AuthFrameworkPlugin) postgresAuth(host string, port int, cred UserPass) (bool, string) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
		host, port, cred.User, cred.Pass, int(p.cfg.Timeout.Seconds()))
	for i := 0; i < p.cfg.Retry; i++ {
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			continue
		}
		db.SetConnMaxLifetime(p.cfg.Timeout)
		db.SetMaxIdleConns(0)
		db.SetMaxOpenConns(1)
		err = db.Ping()
		_ = db.Close()
		if err == nil {
			return true, "PostgreSQL authentication succeeded"
		}
	}
	return false, ""
}

func (p *AuthFrameworkPlugin) trySSH(host string, port int) []AuthEvent {
	start := time.Now()
	candidates := p.credentialCandidates("ssh")
	if len(candidates) == 0 {
		return []AuthEvent{newAuthEvent("ssh", "auth_failed", "config_error", "empty credential candidates", time.Since(start))}
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	for _, c := range candidates {
		ok, ev := p.sshAuth(addr, c)
		if ok {
			return []AuthEvent{{
				Service:    "ssh",
				Username:   c.User,
				Password:   c.Pass,
				Result:     "success",
				Evidence:   ev,
				DurationMS: time.Since(start).Milliseconds(),
			}}
		}
	}
	return []AuthEvent{newAuthEvent("ssh", "auth_failed", "auth_denied", "no credential matched", time.Since(start))}
}

func newAuthEvent(service, result, errorKind, evidence string, d time.Duration) AuthEvent {
	return AuthEvent{
		Service:    service,
		Result:     result,
		ErrorKind:  errorKind,
		Evidence:   evidence,
		DurationMS: d.Milliseconds(),
	}
}

func (p *AuthFrameworkPlugin) sshAuth(addr string, cred UserPass) (bool, string) {
	cfg := &ssh.ClientConfig{
		User:            cred.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cred.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         p.cfg.Timeout,
	}
	for i := 0; i < p.cfg.Retry; i++ {
		client, err := ssh.Dial("tcp", addr, cfg)
		if err == nil {
			_ = client.Close()
			return true, "SSH authentication succeeded"
		}
	}
	return false, ""
}

func (p *AuthFrameworkPlugin) ftpAuth(addr string, cred UserPass) (bool, string) {
	for i := 0; i < p.cfg.Retry; i++ {
		conn, err := net.DialTimeout("tcp", addr, p.cfg.Timeout)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(p.cfg.Timeout))
		r := bufio.NewReader(conn)
		line, _ := r.ReadString('\n')
		if !strings.HasPrefix(line, "220") {
			_ = conn.Close()
			continue
		}
		_, _ = conn.Write([]byte(fmt.Sprintf("USER %s\r\n", cred.User)))
		userResp, _ := r.ReadString('\n')
		_, _ = conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", cred.Pass)))
		passResp, _ := r.ReadString('\n')
		_ = conn.Close()

		if strings.HasPrefix(passResp, "230") {
			return true, "FTP login accepted"
		}
		if strings.HasPrefix(userResp, "230") {
			return true, "FTP login accepted without PASS"
		}
	}
	return false, ""
}

func (p *AuthFrameworkPlugin) credentialCandidates(service string) []UserPass {
	seen := make(map[string]struct{})
	users := p.cfg.Users
	if p.cfg.UserDict != nil {
		if svcUsers, ok := p.cfg.UserDict[strings.ToLower(strings.TrimSpace(service))]; ok && len(svcUsers) > 0 {
			users = svcUsers
		}
	}
	out := make([]UserPass, 0, len(p.cfg.UpPairs)+len(users)*len(p.cfg.Passwords))
	for _, up := range p.cfg.UpPairs {
		key := up.User + "\x00" + up.Pass
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, up)
	}
	for _, u := range users {
		for _, pw := range p.cfg.Passwords {
			pass := strings.ReplaceAll(pw, "{user}", u)
			key := u + "\x00" + pass
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, UserPass{User: u, Pass: pass})
		}
	}
	if p.cfg.MaxTries > 0 && len(out) > p.cfg.MaxTries {
		return out[:p.cfg.MaxTries]
	}
	return out
}

func LoadLinesFile(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		v := strings.TrimSpace(line)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func LoadUserPassFile(path string) ([]UserPass, error) {
	lines, err := LoadLinesFile(path)
	if err != nil {
		return nil, err
	}
	out := make([]UserPass, 0, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, UserPass{
			User: strings.TrimSpace(parts[0]),
			Pass: strings.TrimSpace(parts[1]),
		})
	}
	return out, nil
}
