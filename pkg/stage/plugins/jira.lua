function Analyze(info)
    info.Extra = info.Extra or {}
    
    -- 尝试从 X-ASEN header 获取版本
    local asen = info.Headers["X-ASEN"] or info.Headers["x-asen"]
    if asen then
 
        info.Extra.jiraversion = string.match(asen, "ASEN%s*([%d%.]+)")
        if info.Extra.jiraversion then
 
            return info
        end
    end
    
  
    if info.Banner then
 
        local BannerVersion = string.match(info.Banner, 'data%-version="([%d%.]+)"')
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'data%-name="jira"%s+data%-version="([%d%.]+)"')
        end
 
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'title="JiraVersion"%s*value="([%d%.]+)"')
        end
 
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'title=\\"JiraVersion\\"%s*value=\\"([%d%.]+)\\"')
        end
 
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'type="hidden"%s+title="JiraVersion"%s+value="([%d%.]+)"')
        end
        
        if BannerVersion then
            info.Extra.jiraversion = BannerVersion
            return info
 
        end
    end

 
    local serverHeader = info.Headers["Server"]
    if serverHeader then
      
        info.Extra.jiraversion = string.match(serverHeader, "[Jj]ira.*?([%d%.]+)")
        if info.Extra.jiraversion then
            return info
        end
    end
    return info
end
  