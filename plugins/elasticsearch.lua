function Analyze(info)
    if not info.Headers then
      return info
    end
  
    info.Extra = info.Extra or {}
    local elasticHeader = info.Headers["X-Elastic-Product"]
    
    if elasticHeader then
    --"X-Elastic-Product": "Elasticsearch"
      local version = string.match(elasticHeader, "Elasticsearch%(([%d%.%a]+)%)")
      if version then
        info.Type = version
      end
    end
  
    return info
  end