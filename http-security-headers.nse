description = [[
Checks common HTTP security headers and reports whether they
are present or missing.
]]

author = "Viraj Lokhande"
license = "Same as Nmap"
categories = {"safe", "discovery"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")

    if not response then
        return stdnse.format_output(false, "Unable to connect.")
    end

    if not response.header then
        return stdnse.format_output(false, "No HTTP headers received.")
    end

    local normalized_headers = {}

    for name, value in pairs(response.header) do
        normalized_headers[name:lower()] = value
    end

    local security_headers = {
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy"
    }

    local output = {}

    for _, header in ipairs(security_headers) do
        local value = normalized_headers[header]

        if value then
            table.insert(output,
                string.format("[FOUND] %s: %s", header, value))
        else
            table.insert(output,
                string.format("[MISSING] %s", header))
        end
    end

    return stdnse.format_output(true, output)
end
