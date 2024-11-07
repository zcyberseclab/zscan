function Analyze(info)
  info.Extra = info.Extra or {}
  local serverHeader = info.Headers["Server"]
  if not serverHeader then
    return info
  end
  info.Version = string.match(serverHeader, "Microsoft%-IIS/([%d%.]+)")

  return info
end
