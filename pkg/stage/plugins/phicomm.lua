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
        local title_model =
            string.match(title, "^([Ff][Ii][Rr]%d%d%d[%w%-%s_]*)") or
            string.match(title, "^([Kk]%d[Pp]?[%w%-%s_]*)")

        if title_model then
            info.Version = title_model
            return info
        end
    end

    -- body
    local model =
        -- Web UI
        string.match(body, "Product%s*[Mm]odel%s*</td>%s*<td[^>]*>([^<]+)") or
        -- 文本
        string.match(body, "Model%s*[:：]%s*([%w%-%s_]+)") or
        -- FIR/K 
        string.match(body, "[Ff][Ii][Rr]%d%d%d[%w%-%s_]*") or
        -- K 
        string.match(body, "[Kk]%d[Pp]?[%w%-%s_]*") or
        -- 中文
        string.match(body, "斐讯%s*([%w%-%s_]+)")

    if model then
        model = string.gsub(model, "^%s*(.-)%s*$", "%1")
        model = string.gsub(model, "%s+", " ")
        info.Version = string.upper(model)
    end

    return info
end