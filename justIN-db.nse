-- HEAD -- -- Meta data --

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
-- @usage
-- checks for all dbms 
-- nmap --script=justIN-db <targets>

-- checks for popular dbms 
-- sudo nmap --script=justIN-db --script-args check=popular <targets>

-- limited dbms scan  
-- sudo nmap --script=justIN-db --script-args count=5 <targets>

---
-- @output
-- PORT     STATE   SERVICE     VERSION
-- 3306/tcp open    MySQL       MySQL 5.7 
-- | /*

-- optional nse script like --script
-- dependencies = {"smb-brute"}

-- setting up local variables


-- RULE --returns only true or false...if true it executes the ACTION



-- ACTION --
