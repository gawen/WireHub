function help()
    print("Usage: wh check-wg")
end

if arg[2] == 'help' then
    return help()
end

if check_wg() then
    print("OK! WireGuard is installed.")
else
    return -1
end
