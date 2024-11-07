function Analyze(info)
  info.Extra = info.Extra or {}

  local modelName = string.match(info.Banner, "modelName=\"([^\"]+)\"")
  local modelDesc = string.match(info.Banner, "modelDesc=\"([^\"]+)\"")
  
  if modelName then
    info.Extra.model = modelName
  end
  
  if modelDesc then
    info.Extra.description = modelDesc
  end

  return info
end
