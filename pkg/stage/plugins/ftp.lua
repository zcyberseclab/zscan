-- FTP 匿名登录检测函数
function check_anonymous_login(ip, port)
    if not ip or not port then
        print("[FTP] Invalid input: ip=", ip or "nil", ", port=", port or 0)
        return nil
    end

    print("[FTP] Checking anonymous login for", ip..":", port)
    
    -- 尝试建立 TCP 连接
    local sock, err = tcp.connect(ip, port, 5)  -- 5秒超时
    if not sock then
        print("[FTP] Failed to connect:", err or "unknown error")
        return nil
    end

    -- 读取欢迎信息
    local welcome = sock:receive("*l")
    if not welcome or not string.match(welcome, "^220") then
        print("[FTP] Invalid welcome message:", welcome or "nil")
        sock:close()
        return nil
    end
    print("[FTP] Welcome message:", welcome)

    -- 发送用户名 "anonymous"
    sock:send("USER anonymous\r\n")
    local user_resp = sock:receive("*l")
    if not user_resp or not string.match(user_resp, "^331") then
        print("[FTP] USER failed:", user_resp or "nil")
        sock:close()
        return nil
    end
    print("[FTP] USER response:", user_resp)

    -- 发送密码 (邮箱格式)
    sock:send("PASS test@example.com\r\n")
    local pass_resp = sock:receive("*l")
    print("[FTP] PASS response:", pass_resp or "nil")
    
    -- 检查是否登录成功
    if pass_resp and string.match(pass_resp, "^230") then
        print("[FTP] Anonymous login successful!")
        
        -- 尝试列出目录内容
        sock:send("LIST\r\n")
        local list_resp = sock:receive("*l")
        local dir_content = ""
        
        if list_resp and string.match(list_resp, "^150") then
            print("[FTP] LIST command accepted:", list_resp)
            -- 读取目录内容
            while true do
                local line = sock:receive("*l")
                if not line or line == "" then break end
                dir_content = dir_content .. line .. "\n"
            end
            print("[FTP] Directory listing:\n", dir_content)
        else
            print("[FTP] LIST command failed:", list_resp or "nil")
        end
        
        sock:send("QUIT\r\n")
        sock:close()
        
        local result = {
            CVEID = "FTP-ANONYMOUS-LOGIN",
            Severity = "medium",
            Type = "Anonymous FTP Access",
            Extra = {
                ["Welcome Banner"] = welcome,
                ["Directory Content"] = dir_content ~= "" and dir_content or "Empty or access denied"
            }
        }
        print("[FTP] Vulnerability found:", result.CVEID)
        return result
    end

    print("[FTP] Anonymous login failed")
    sock:send("QUIT\r\n")
    sock:close()
    return nil
end

-- 主分析函数
function Analyze(info)
    -- 检查参数
    if not info or not info.IP or not info.Port then
        print("[FTP] Invalid ServiceInfo: missing IP or Port")
        return info
    end

    print("[FTP] Analyzing service on", info.IP..":", info.Port)
    
    -- 检查漏洞
    local vulns = {}
    
    -- 检查匿名登录
    local result = check_anonymous_login(info.IP, info.Port)
    if result then
        table.insert(vulns, result)
        print("[FTP] Added vulnerability:", result.CVEID)
    end
    
    -- 如果发现漏洞，添加到结果中
    if #vulns > 0 then
        info.Vulnerabilities = vulns
        print("[FTP] Total vulnerabilities found:", #vulns)
    else
        print("[FTP] No vulnerabilities found")
    end

    return info
end

 