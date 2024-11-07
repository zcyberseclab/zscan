function Analyze(info)
    if not info.Headers then
      return info
    end
  
    info.Extra = info.Extra or {}
    local serverHeader = info.Headers["Server"]
    
    if serverHeader then
      -- Extract Jetty version (e.g., "Jetty(9.4.50.v20221201)")
      local version = string.match(serverHeader, "uc-httpd%(([%d%.%a]+)%)")
      if version then
        info.Version = version
      end
    end
  
    return info
  end
  