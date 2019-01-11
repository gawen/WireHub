#!/usr/bin/env lua

require('wh')
require('helpers')

local d, iaddr, url = wh.upnp.discover_igd(1)

if not d then
    print("no UPnP device detected")
    return
end

for _, r in ipairs(wh.upnp.list_redirects(d)) do
    if r.iaddr == iaddr then
        printf('remove :%d -> %s:%d', r.eport, r.iaddr, r.iport)
        wh.upnp.remove_redirect(d, r)
    end
end

