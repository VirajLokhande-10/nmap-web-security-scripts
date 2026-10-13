description = [[
Admin Panel Finder
Custom NSE script to detect common exposed admin pages.
]]

author = "Viraj Lokhande"
license = "Same as Nmap"
categories = {"safe", "discovery"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)

    local admin_paths = {
        "/admin",
        "/login",
        "/administrator",
        "/admin/login",
        "/dashboard",
        "/wp-admin",
        "/phpmyadmin",
        "/cpanel",
        "/adminpanel",
        "/backend"
    }

    local output = {}
    local found = 0

    table.insert(output, "Admin Panel Finder")
    table.insert(output, "------------------------------")

    for _, path in ipairs(admin_paths) do

        local response = http.get(host, port, path)

        if response then

            local status = response.status or 0
            local body = string.lower(response.body or "")

            -- Ignore common error pages
            if body:find("404") or
               body:find("not found") or
               body:find("page not found") then
                goto continue
            end

            -- HTTP 401 = Exists but authentication required
            if status == 401 then
                found = found + 1
                table.insert(output,
                    string.format("[PROTECTED] %-18s (HTTP %d)", path, status))
                goto continue
            end

            -- HTTP 403 = Exists but access forbidden
            if status == 403 then
                found = found + 1
                table.insert(output,
                    string.format("[FORBIDDEN] %-18s (HTTP %d)", path, status))
                goto continue
            end

            -- HTTP 200 = Validate page content
            if status == 200 then

                local valid = false

                if path == "/login" then
                    valid = body:find("sign in")
                          or body:find("log in")
                          or body:find("username")
                          or body:find("password")
                elseif path == "/wp-admin" then
                    valid = body:find("wordpress")
                          or body:find("wp%-admin")
                elseif path == "/phpmyadmin" then
                    valid = body:find("phpmyadmin")
                elseif path == "/cpanel" then
                    valid = body:find("cpanel")
                elseif path == "/dashboard" then
                    valid = body:find("dashboard")
                elseif path == "/administrator" then
                    valid = body:find("administrator")
                elseif path == "/admin" or path == "/adminpanel" then
                    valid = body:find("admin")
                elseif path == "/backend" then
                    valid = body:find("backend")
                elseif path == "/admin/login" then
                    valid = body:find("admin")
                          and body:find("login")
                end

                if valid then
                    found = found + 1
                    table.insert(output,
                        string.format("[FOUND] %-20s (HTTP %d)", path, status))
                end
            end
        end

        ::continue::
    end

    table.insert(output, "")
    table.insert(output,
        string.format("Total Admin Pages Found: %d", found))

    if found == 0 then
        table.insert(output, "No common admin pages detected.")
    elseif found <= 2 then
        table.insert(output, "Low Exposure Risk")
    elseif found <= 5 then
        table.insert(output, "Medium Exposure Risk")
    else
        table.insert(output, "High Exposure Risk")
    end

    return stdnse.format_output(true, output)

end
