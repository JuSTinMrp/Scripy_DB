-- HEAD -- -- Meta data --

description = [[
Powerful Database Detection Script by cyb3rr4v
]]

author= "Ram Praveen (cyberrav)"
categories = {"default", "discovery", "safe"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

args = {
    {arg = "--count", name = "count", desc = "Limit the no of dbms scan", type = "number"},
    {arg = "--check", name = "filter", desc = "'popular' -> Only checks for popular dbms", type = "string"},
}


---
-- @output
-- PORT     STATE   SERVICE     VERSION
-- 3306/tcp open    MySQL       MySQL 5.7 


-- opional nse script like --script
-- dependencies = {"smb-brute"}

-- setting up local variables
local nmap = require("nmap")
local shortport = require("shortport")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")
local http = require("http")
local mysql = require("mysql")
local pgsql = require("pgsql")


-- require("ms-sql-info")
-- require("oracle")

-- RULE --returns only true or false...if true it executes the ACTION

hostrule = function(host)
    return port.protocol == "tcp" and (port.number == 3306 or port.number == 5432 or port.number == 1433 or port.number == 1521)
end


-- ACTION --

action = function(host, port)
    if port.number == 3306 then
    local result = mysql.version()
    if result then
        print(string.format("MySQL version detected on %s:%d - %s", host.ip, port.number, result))
end
    elseif port.number == 5432 then
    local result = pgsql.version()
    if result then
        print(string.format("PostgreSQL version detected on %s:%d - %s", host.ip, port.number, result))
end
    elseif port.number == 1433 then
    local result = ms_sql.version()
    if result then
        print(string.format("Microsoft SQL Server detected on %s:%d - %s", host.ip, port.number, result))
end
    elseif port.number == 1521 then
    local result = oracle.version()
    if result then
        print(string.format("Oracle Database version detected on %s:%d - %s", host.ip, port.number, result))
    end
    end
end
