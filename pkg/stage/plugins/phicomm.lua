function Analyze(info)
    info.Extra = info.Extra or {}

    local body = info.Body or ""
    if body == "" then
        return info
    end

    --  <title> 
    local title = string.match(
        body,
        "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]+)</[Tt][Ii][Tt][Ll][Ee]>"
    )

    if title then
        title = string.gsub(title, "^%s*(.-)%s*$", "%1")

        if string.match(title, "^FIR[%w%-]+") or
           string.match(title, "^K%dP?$") or
           string.match(title, "^K3$") then
            info.Version = title
            return info
        end
    end

    -- body
    local model =
        -- Web UI
        string.match(body, "Product%s*[Mm]odel%s*</td>%s*<td[^>]*>([^<]+)") or
        -- 文本
        string.match(body, "Model%s*[:：]%s*([%w%-_]+)") or
        -- FIR
        string.match(body, "[Ff][Ii][Rr]%d%d%d[%w]?") or
        -- K
        string.match(body, "[Kk]%d[Pp]?") or
        -- 中文
        string.match(body, "斐讯%s*([%w%-_]+)")

    if model then
        info.Version = string.upper(model)
    end

    return info
end