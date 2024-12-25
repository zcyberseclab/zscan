function Analyze(info)
    info.Extra = info.Extra or {}
    
 
    if info.Banner then
     
        local BannerVersion = string.match(info.Banner, '/administrator/manifests/files/joomla%.xml[^>]+version="([%d%.]+)"')
        
 
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, '<meta%s+name="generator"%s+content="[Jj]oomla!?%s*([%d%.]+)"')
        end
 
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'This is Joomla!?%s+([%d%.]+)')
        end
        
  
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, '/language/[^/]+/[^/]+%.xml[^>]+version="([%d%.]+)"')
        end
        
        -- 从 JavaScript 变量获取版本
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'var%s+joomla_version%s*=%s*[\'"]([%d%.]+)[\'"]')
        end

        -- 从 component 路径获取版本
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, '/components/com_[^/]+/joomla%.xml[^>]+version="([%d%.]+)"')
        end
        
        if BannerVersion then
            info.Extra.joomlaversion = BannerVersion
            return info
        end
    end

 
    local encodedBy = info.Headers["X-Content-Encoded-By"] or info.Headers["x-content-encoded-by"]
    if encodedBy then
        info.Extra.joomlaversion = string.match(encodedBy, "[Jj]oomla!?%s*([%d%.]+)")
        if info.Extra.joomlaversion then
            return info
        end
    end
 
    local serverHeader = info.Headers["Server"]
    if serverHeader then
        info.Extra.joomlaversion = string.match(serverHeader, "[Jj]oomla!?.*?([%d%.]+)")
        if info.Extra.joomlaversion then
            return info
        end
    end
 

    return info
end