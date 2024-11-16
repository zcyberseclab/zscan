function Analyze(info)
    info.Extra = info.Extra or {}
    info.Extra.snapshot = "/-wvhttp-01-/GetOneShot?image_size=640x480&frame_count=1000000000"
    info.Extra.adminpage = "/admin/index.html?lang=en"
    
    if info.Banner then
        local model = info.Banner:match("Network Camera ([%w%-]+)")
        if model then
            info.Extra.model = model
        end
        
        if info.Banner:find("/viewer/live/en/live.html") then
            info.Extra.viewer_url = "/viewer/live/en/live.html"
        end
        
        if info.Banner:find("/viewer/admin/en/admin.html") then
            info.Extra.admin_viewer = "/viewer/admin/en/admin.html"
        end
        
        if info.Banner:find("/admintools/en/index.html") then
            info.Extra.admin_tools = "/admintools/en/index.html"
        end
    end

    return info
end
