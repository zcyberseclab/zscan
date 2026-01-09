function Analyze(info)
    info.Extra = info.Extra or {}

    local body = info.Body or ""
    if body == "" then
        return info
    end

    -- Extract title content (e.g., "K1", "FIR302B A2", "K2P Web Service - Welcome")
    local title = string.match(body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]+)</[Tt][Ii][Tt][Ll][Ee]>")
    if not title then
        return info
    end

    -- Trim whitespace
    title = string.gsub(title, "^%s*(.-)%s*$", "%1")

    if (
        -- FIR 
        string.match(title, "^FIR") or
        
        -- K1/K2/K3
        string.match(title, "^K[123]$") or
        
        -- K2P 
        title == "K2P" or
        title == "K2P Web Service - Welcome" or
        title == "K2P 路由器"
    ) then
        info.Version = title
    end

    return info
end