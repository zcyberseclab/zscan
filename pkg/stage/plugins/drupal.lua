function Analyze(info)
    info.Extra = info.Extra or {}
    
    -- 尝试从 response Banner 获取版本
    if info.Banner then
        -- 从 meta 标签获取版本号
        local BannerVersion = string.match(info.Banner, 'content="Drupal%s*([%d%.x%-]+)"')
        
        -- 从 site-version class 获取版本
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'class="site%-version">([%d%.x%-]+)')
        end
        
        -- 从 CHANGELOG.txt 获取版本
        if not BannerVersion and string.match(info.Banner, 'Drupal%s+1%.0%.0') then
            BannerVersion = "1.0.0"
        end
        
        if BannerVersion then
            info.Extra.drupalversion = BannerVersion
            return info
        end
    end

    -- 尝试从 X-Generator header 获取版本
    local generator = info.Headers["X-Generator"] or info.Headers["x-generator"]
    if generator then
        info.Extra.drupalversion = string.match(generator, "Drupal%s*([%d%.x%-]+)")
        if info.Extra.drupalversion then
            return info
        end
    end

    -- 尝试从 Server header 获取版本
    local serverHeader = info.Headers["Server"]
    if serverHeader then
        info.Extra.drupalversion = string.match(serverHeader, "Drupal.*?([%d%.x%-]+)")
        if info.Extra.drupalversion then
            return info
        end
    end
    return info
end