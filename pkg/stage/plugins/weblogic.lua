function Analyze(info)
    info.Extra = info.Extra or {}
    local serverHeader = info.Headers["Server"]
    if not serverHeader then
      return info
    end
    info.Version = string.match(serverHeader, "WebLogic Server/([%d%.]+)")
  
    return info
  end
  