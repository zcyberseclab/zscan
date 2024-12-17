function Analyze(info)
    info.Extra = info.Extra or {}
    
    -- 尝试从 X-ASEN header 获取版本
    local asen = info.Headers["X-ASEN"] or info.Headers["x-asen"]
    if asen then
        info.Version = string.match(asen, "ASEN%s*([%d%.]+)")
        if info.Version then
            return info
        end
    end
    
    -- 尝试从 Server header 获取版本
    local serverHeader = info.Headers["Server"]
    if serverHeader then
        info.Version = string.match(serverHeader, "[Jj]ira.*?([%d%.]+)")
    end

    return info
end
  