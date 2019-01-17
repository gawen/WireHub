local dbg_keys = {idx=1}
function wh.key(k_or_p, n)
    local k, p

    if type(k_or_p) == 'table' then
        p = k_or_p
        k = p.k
    else
        p = nil
        k = k_or_p

        if k == nil then
            return nil
        end
    end

    if not p and n then
        p = n.kad:get(k)
    end

    if p then
        if p.hostname then
            return p.hostname
        elseif p.ip then
            return string.format("<ip %s>", p.ip)
        end
    end

    local b64 = wh.tob64(k)
    b64 = string.sub(b64, 1, 10)
    return b64
end

