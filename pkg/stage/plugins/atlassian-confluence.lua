function Analyze(info)
    info.Extra = info.Extra or {}
    
  
    if info.Banner then
   
        local BannerVersion = string.match(info.Banner, 'name="ajs%-version%-number"%s+content="([%d%.]+)"')
        
        
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'Atlassian%s+Confluence%s+([%d%.%-]+)')
        end
        
        if BannerVersion then
            info.Extra.confluenceversion = BannerVersion
            return info
        end
    end
 
    local confluenceHeader = info.Headers["X-Confluence-Request-Time"] or info.Headers["x-confluence-request-time"]
    if confluenceHeader then
        info.Extra.confluence = true
    end

  
    local serverHeader = info.Headers["Server"]
    if serverHeader then
        info.Extra.confluenceversion = string.match(serverHeader, "[Cc]onfluence.*?([%d%.]+)")
        if info.Extra.confluenceversion then
            return info
        end
    end
    return info
end
