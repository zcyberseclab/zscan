function Analyze(info)
    info.Extra = info.Extra or {}
  
    local modelName = string.match(info.Banner, "\"([^\"]+)\"ehang.io\"([^\"]+)\"")

    if modelName then
      info.Extra.model = modelName
    end
    
    return info
  end
  