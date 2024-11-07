function Analyze(info)
  if not info.Headers then
    return info
  end

  info.Extra = info.Extra or {}
  local serverHeader = info.Headers["Server"]
  
  if serverHeader then
    local version = string.match(serverHeader, "AliyunOSS%(([%d%.%a]+)%)")
    if version then
      info.Version = version
    end
  end

  return info
end
  