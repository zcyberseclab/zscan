function Analyze(info)
    info.Extra = info.Extra or {}
  
    local modelName = string.match(info.Banner, "\"([^\"]+)\"vite\"([^\"]+)\"")

    if modelName then
      info.Extra.model = modelName
    end
    
    return info
  end
  