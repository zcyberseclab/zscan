function Analyze(info)
    if not info.Port then
        return info
    end

    -- 检查是否是SSH服务
    if info.Service ~= "ssh" then
        return info
    end

    info.Extra = info.Extra or {}
    
    -- 常见用户名和密码组合
    local users = {"root", "admin", "ubuntu", "test"}
    local passwords = {"123456", "admin", "password", "root", "123123"}
    
    -- 记录成功的结果
    local success = {}
    
    -- 遍历用户名和密码组合
    for _, user in ipairs(users) do
        for _, pass in ipairs(passwords) do
            local result = try_ssh_login(info.Host, info.Port, user, pass)
            if result.success then
                table.insert(success, {
                    username = user,
                    password = pass
                })
            end
        end
    end
    
    -- 如果有成功的组合，添加到Extra信息中
    if #success > 0 then
        info.Extra["ssh_weak_pass"] = success
        info.Risk = "HIGH"
        info.RiskDesc = "Found weak SSH credentials"
    end
    
    return info
end

-- SSH登录尝试函数
function try_ssh_login(host, port, username, password)
    local ssh2 = require("ssh2")
    
    local config = {
        host = host,
        port = port,
        username = username,
        password = password,
        timeout = 5000  -- 5秒超时
    }
    
    local result = {
        success = false,
        error = nil
    }
    
    -- 创建SSH连接
    local client = ssh2.new()
    
    -- 设置超时处理
    local ok, err = pcall(function()
        client:connect(config)
    end)
    
    if ok then
        -- 尝试认证
        ok, err = pcall(function()
            client:auth_password(username, password)
        end)
        
        if ok then
            result.success = true
        end
        
        -- 关闭连接
        client:disconnect()
    end
    
    return result
end
