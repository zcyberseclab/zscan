function Analyze(info)
    info.Extra = info.Extra or {}
    
    -- 尝试从 banner获取版本
    local banner_info = info.Banner
    if banner_info then
        local BannerVersion = string.match(banner_info, 'min%.css%?ver=([0-9.]+)')
        if not BannerVersion then
            BannerVersion = string.match(info.Banner, 'min%.js%?ver=([0-9.]+)')
        end
        
        if BannerVersion then
            info.Extra.wordpressversion = BannerVersion
            return info
        end
    end
end
  