function Analyze(info)
    if not info.Headers then
      return info
    end
  
    info.Extra = info.Extra or {}
    local serverHeader = info.Headers["Server"]
    
    if serverHeader then
      -- Extract Jetty version (e.g.,  "Server": "squid/4.14",)
      local version = string.match(serverHeader, "Tengine%(([%d%.%a]+)%)")
      if version then
        info.Version = version
      end
    end
  
    return info
  end
  