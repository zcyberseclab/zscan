function Analyze(info)
    info.Extra = info.Extra or {}

    local banner = info.Banner or ""
    if banner == "" then
        return info
    end

    -- title
    local title = string.match(banner, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]+)</[Tt][Ii][Tt][Ll][Ee]>")
    if title then
        title = string.gsub(title, "^%s*(.-)%s*$", "%1"):gsub("\\n", "")
        local title_ver = string.match(title:lower(), "ad report ([%d%.]+)")
        if title_ver then
            info.Extra["AdReportVersion"] = title_ver
            info.Version = title_ver
            return info
        end
    end

    -- div
    local div_ver = string.match(banner:lower(), "sangfor%-ad%-([%d%.]+)")
    if div_ver then
        info.Extra["AdReportVersion"] = div_ver
        info.Version = div_ver
        return info
    end

    -- body
    local std_ver = string.match(banner:lower(), "ad report ([%d%.]+)")
    if std_ver then
        info.Extra["AdReportVersion"] = std_ver
        info.Version = std_ver
        return info
    end

    return info
end