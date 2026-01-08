function Analyze(info)
    info.Extra = info.Extra or {}

    local body = info.Body or ""
    if body == "" then
        return info
    end

    -- Extract title content (e.g., "K1", "FIR302B A2", "K2P Web Service - Welcome")
    local title = string.match(body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]+)</[Tt][Ii][Tt][Ll][Ee]>")
    if title then
        -- Trim whitespace
        title = string.gsub(title, "^%s*(.-)%s*$", "%1")
        -- Only set version if it's a valid Phicomm model (prevent noise)
        if string.match(title, "^FIR") or string.match(title, "^K[123]$") or string.match(title, "^K2P") or string.match(title, "^K3$") then
            info.Version = title
        end
    end

    return info
end