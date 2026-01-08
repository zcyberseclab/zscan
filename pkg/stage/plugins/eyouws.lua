function Analyze(info)
    info.Extra = info.Extra or {}

    local serverHeader = info.Headers["Server"]
    if not serverHeader then
        return info
    end

    -- Match patterns like: eyouws/1.20.1, eyouws/1.20.2, eyouws/1.22.0
    local version = string.match(serverHeader, "eyouws/([%d%.]+)")
    if version then
        version = string.gsub(version, "^[Vv]", "")
        info.Version = version
    end

    return info
end