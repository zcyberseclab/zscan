function Analyze(info)
  info.Extra = info.Extra or {}
  local serverHeader = info.Headers["Server"]
  if not serverHeader then
    return info
  end
  -- "Server": "TornadoServer/6.2",
  info.Version = string.match(serverHeader, "thttpd/([%d%.]%d+)")

  return info
end
