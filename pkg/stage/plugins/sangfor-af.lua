function Analyze(info)
    info.Extra = info.Extra or {}

    local banner = info.Banner or ""
    if banner == "" then
        return info
    end

    local full_ver = string.match(banner, "SANGFOR%-AF([%d%.]+%s*R%d+%s*Build%d+)")
    if full_ver then
        info.Extra["SangforVersion"] = full_ver
        info.Version = full_ver
        return info
    end

    local simple_ver = string.match(banner, "SANGFOR%-AF%s*([%d%.]+)")
    if simple_ver then
        info.Extra["SangforVersion"] = simple_ver
        info.Version = simple_ver
        return info
    end

    local title_ver = string.match(banner, "<[Tt][Ii][Tt][Ll][Ee][^>]*>SANGFOR AF ([%d%.]+)</[Tt][Ii][Tt][Ll][Ee]>")
    if title_ver then
        info.Extra["SangforVersion"] = title_ver
        info.Version = title_ver
    end

    return info
end