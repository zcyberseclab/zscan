local function extractNginxVersion(headers)
  if type(headers) ~= "table" then
    return nil
  end

  local serverHeader = headers["Server"]
  if not serverHeader then
    return nil
  end

  local version = string.match(serverHeader, "nginx/([%d%.]+)")
  return version
end

 
function Analyze(info)
  if not info then
    return info
  end
  if not info.Headers then
    return info
  end
  local version = extractNginxVersion(info.Headers)
  if version then
    info.Version = version
  end

  return info
end
