function Analyze(info)
  info.Extra = info.Extra or {}
  local serverHeader = info.Headers["Server"]
  if not serverHeader then
    return info
  end
  info.Version = string.match(serverHeader, "thttpd/([%d%.]+[a-z]?%s+%d+[a-z]+%d+)")

  return info
end
