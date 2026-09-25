--[[
    Fixture de conformité.

    Charge le VRAI code de l'agent (shared/crypto.lua, shared/constants.lua,
    shared/protocol.lua) et émet, en JSON, les chaînes canoniques et les
    signatures produites pour un jeu de cas figés. Le test Node recalcule les
    mêmes valeurs et compare octet par octet.

    Sans ce test, une divergence de protocole ne se manifeste qu'en production,
    sous la forme d'un 401 inexplicable côté opérateur.

    Usage : lua5.4 agent_signature.lua <chemin vers zshield-agent>
]]

local agentRoot = arg[1] or '../../../../zshield-agent'

-- L'agent attend `json` comme global fourni par FXServer ; les modules chargés
-- ici (crypto, constants, protocol) ne s'en servent pas, mais constants.lua est
-- chargé en premier et ne doit pas échouer sur un global manquant.
json = { encode = function() return '{}' end, decode = function() return {} end }

local function loadModule(relative)
    local path = agentRoot .. '/' .. relative
    local chunk, err = loadfile(path)
    if not chunk then error(('impossible de charger %s : %s'):format(path, tostring(err))) end
    chunk()
end

loadModule('shared/constants.lua')
loadModule('shared/crypto.lua')
loadModule('shared/protocol.lua')

local Crypto = ZShield.Crypto
local Protocol = ZShield.Protocol

local SECRET = 'test-secret-do-not-use-in-production-0123456789'

local cases = {
    {
        name = 'handshake POST avec corps',
        method = 'POST',
        path = '/v1/agents/handshake',
        query = '',
        agentId = 'agt_01hxxxxxxxxxxxxxxxxxxxxxxx',
        serverId = 'srv_01hxxxxxxxxxxxxxxxxxxxxxxx',
        keyId = 'key_01hxxxxxxxxxxxxxxxxxxxxxxx',
        timestamp = 1767225600,
        nonce = 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
        body = '{"protocol_version":1,"kind":"handshake","payload":{}}',
    },
    {
        name = 'config GET avec query',
        method = 'GET',
        path = '/v1/agents/config',
        query = 'version=3',
        agentId = 'agt_01hxxxxxxxxxxxxxxxxxxxxxxx',
        serverId = 'srv_01hxxxxxxxxxxxxxxxxxxxxxxx',
        keyId = 'k1',
        timestamp = 1767225601,
        nonce = '00112233445566778899aabbccddeeff',
        body = '',
    },
    {
        name = 'alerts POST, UTF-8 et accents',
        method = 'POST',
        path = '/v1/agents/alerts',
        query = '',
        agentId = 'agt_01hxxxxxxxxxxxxxxxxxxxxxxx',
        serverId = 'srv_01hxxxxxxxxxxxxxxxxxxxxxxx',
        keyId = 'key_rotated_2',
        timestamp = 1767225602,
        nonce = 'ffeeddccbbaa99887766554433221100',
        -- Un résumé accentué : si une couche re-sérialise le JSON en échappant
        -- l'Unicode, l'empreinte change et la signature devient invalide.
        body = '{"payload":{"alerts":[{"summary":"Téléportation détectée à 250 m/s"}]}}',
    },
}

local out = { cases = {}, responses = {} }

for _, case in ipairs(cases) do
    local bodyHash = Crypto.sha256hex(case.body)
    local canonical = Protocol.canonicalRequest({
        method = case.method,
        path = case.path,
        query = case.query,
        agentId = case.agentId,
        serverId = case.serverId,
        keyId = case.keyId,
        timestamp = case.timestamp,
        nonce = case.nonce,
        bodyHash = bodyHash,
    })

    out.cases[#out.cases + 1] = {
        name = case.name,
        method = case.method,
        path = case.path,
        query = case.query,
        agent_id = case.agentId,
        server_id = case.serverId,
        key_id = case.keyId,
        timestamp = case.timestamp,
        nonce = case.nonce,
        body = case.body,
        body_hash = bodyHash,
        canonical = canonical,
        signature = Crypto.hmachex(SECRET, canonical),
    }
end

-- Sens plateforme -> agent : ce que l'agent va vérifier.
local responseCases = {
    { status = 200, requestId = 'req_0123456789ab', timestamp = 1767225600,
      nonce = 'deadbeefdeadbeefdeadbeefdeadbeef',
      body = '{"ok":true,"server_time":1767225600,"request_id":"req_0123456789ab"}' },
    { status = 401, requestId = 'req_ffffffffffff', timestamp = 1767225700,
      nonce = 'cafebabecafebabecafebabecafebabe',
      body = '{"ok":false,"error":"E_AUTH_REPLAY","message":"nonce already seen"}' },
}

for _, case in ipairs(responseCases) do
    local bodyHash = Crypto.sha256hex(case.body)
    local canonical = Protocol.canonicalResponse({
        status = case.status,
        requestId = case.requestId,
        timestamp = case.timestamp,
        nonce = case.nonce,
        bodyHash = bodyHash,
    })
    out.responses[#out.responses + 1] = {
        status = case.status,
        request_id = case.requestId,
        timestamp = case.timestamp,
        nonce = case.nonce,
        body = case.body,
        body_hash = bodyHash,
        canonical = canonical,
        signature = Crypto.hmachex(SECRET, canonical),
    }
end

-- Encodeur JSON minimal : la fixture ne doit dépendre d'aucune bibliothèque.
local function escape(s)
    return (s:gsub('[%c"\\]', function(c)
        local map = { ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }
        return map[c] or string.format('\\u%04x', string.byte(c))
    end))
end

local function encode(value)
    local t = type(value)
    if t == 'number' then return tostring(value) end
    if t == 'string' then return '"' .. escape(value) .. '"' end
    if t ~= 'table' then return 'null' end

    if #value > 0 then
        local parts = {}
        for _, v in ipairs(value) do parts[#parts + 1] = encode(v) end
        return '[' .. table.concat(parts, ',') .. ']'
    end

    local keys = {}
    for k in pairs(value) do keys[#keys + 1] = k end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do
        parts[#parts + 1] = '"' .. escape(k) .. '":' .. encode(value[k])
    end
    return '{' .. table.concat(parts, ',') .. '}'
end

out.secret = SECRET
print(encode(out))
