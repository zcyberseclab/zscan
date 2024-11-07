function Analyze(info)
  info.Extra = info.Extra or {}
  info.Extra.snapshot = "/oneshotimage1?COUNTER"
  local serverHeader = info.Headers["Server"]
  if not serverHeader then
    return info
  end
  info.Version = string.match(serverHeader, "gen5th/([%d%.]+)")

  return info
end
