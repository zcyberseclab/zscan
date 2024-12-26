function Analyze(info)
  -- Check if info.Headers exists
  if not info.Headers then
    return info
  end

  info.Extra = info.Extra or {}
  local serverHeader = info.Headers["Server"]
  local phpHeader = info.Headers["X-Powered-By"]
  
  if serverHeader then
 
    local apacheversion = string.match(serverHeader, "Apache/([%d%.]+)")
    info.Version = apacheversion
    info.Extra["Apache"] = apacheversion

    local opensslVer = string.match(serverHeader, "OpenSSL/([%d%.]+)")
    if opensslVer then
        info.Extra["OpenSSL"] = opensslVer
    end
    
    -- Check for PHP in Server header
    local phpVer = string.match(serverHeader, "PHP/([%d%.]+)")
    if phpVer then
        info.Extra["PHP"] = phpVer
    end
    
    -- Check X-Powered-By header for PHP version
    if not phpVer and phpHeader then
      phpVer = string.match(phpHeader, "PHP/([%d%.]+)")
      if phpVer then
        info.Extra["PHP"] = phpVer
      end
    end
    
    -- Add OS info if available
    local os = string.match(serverHeader, "%(([^%)]+)%)")
    if os then
      os = string.lower(os)  -- Convert OS string to lowercase
      info.Extra["OS"] = os
      info.OS = os
    end
    
 
  end

  return info
end
