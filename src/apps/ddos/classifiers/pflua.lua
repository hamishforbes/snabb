local log           = require("lib.log")
local log_info      = log.info
local log_warn      = log.warn
local log_error     = log.error
local log_critical  = log.critical

local pf            = require("pf")
local bucket        = require("apps.ddos.lib.bucket")

local _M = {
    _VERSION = "0.01",
    _TYPE = "pflua",
}

local mt = { __index = _M }

function _M.new(rules)
    local self = {
        rules      = {},
        buckets    = {},
        rule_count = 0
    }

    return setmetatable(self, mt)
end

function _M.parse_rules(self, rules)
    -- For each input rule
    for rule_num, rule in ipairs(rules) do
        log_info("Compiling rule %s with filter '%s'", rule.filter)
        -- Compile PF filter and assert validity
        local filter = pf.compile_filter(rule.filter)
        assert(filter)

        -- Assign to list of rules to be scanned
        self.rules[rule_num] = filter

        -- Create new bucket with rule thresholds
        self.buckets[rule_num] = bucket.new(rule)
    end
    self.rule_count = #self.rules
end

function _M.match(self, packet)
    local rules = self.rules
    local buckets = self.buckets
    local rule_count = self.rule_count

    -- For each rule
    for i = 1, rule_count do
        local rule = rules[i]
        -- Check if rule matches against packet data and length
        if rule(packet.data, packet.length) then
            -- Return relevant bucket if match
            return buckets[i]
        end
    end
    -- Otherwise return nothing
    return nil
end

function _M.periodic(self)
    -- Calculate bucket timers
    for i = 1, self.rule_count do
        local bucket = buckets[i]
        bucket:calculate_rate()
        bucket:check_violation()
    end
end

return _M
