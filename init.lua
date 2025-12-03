--- === SSHSignatures ===
---
--- Helpers to use `ssh-agent` to list public keys, sign data, or lock it
---
--- ## Usage
---
--- ```lua
--- hs.loadSpoon("SSHSignatures")
--- spoon.SSHSignatures:sshAgentListIdentities(function (keys)
---   print(hs.inspect(keys))
---   spoon.SSHSignatures:sshAgentSign("some data to sign", keys[1], "file", function (signature)
---     print(hs.inspect(signature))
---   end)
--- end)
--- ```

local obj={}
obj.__index = obj

-- Metadata
obj.name = "SSHSignatures"
obj.version = "0.1"
obj.author = "eric"
obj.license = "MIT - https://opensource.org/licenses/MIT"


local log = hs.logger.new("sshAgent")
-- log.level = 'info'
-- log.level = 'debug'

local socketLog = hs.logger.new("sshAgentSock")
-- socketLog.level = 'info'
-- socketLog.level = 'debug'


--- SSHSignatures.socketPath (string)
--- Variable
---  Unix socket path to `ssh-agent`
--- Notes:
---  * Defaults to `os.getenv("SSH_AUTH_SOCK")`
obj.socketPath = os.getenv("SSH_AUTH_SOCK")


local SSH_AGENT_CONST

function findEnumValue(type, value, debug)
  for k, v in pairs(SSH_AGENT_CONST[type]) do
    if v == value then return k end
  end
  if not debug then return nil end
  return ("(Unknown SSH_AGENT_CONST.%s = %d)"):format(type, value)
end

SSH_AGENT_CONST = {
  TYPE = {
    -- Requests
    SSH_AGENTC_REQUEST_IDENTITIES                  = 11,
    SSH_AGENTC_SIGN_REQUEST                        = 13,
    SSH_AGENTC_ADD_IDENTITY                        = 17,
    SSH_AGENTC_REMOVE_IDENTITY                     = 18,
    SSH_AGENTC_REMOVE_ALL_IDENTITIES               = 19,
    SSH_AGENTC_ADD_ID_CONSTRAINED                  = 25,
    SSH_AGENTC_ADD_SMARTCARD_KEY                   = 20,
    SSH_AGENTC_REMOVE_SMARTCARD_KEY                = 21,
    SSH_AGENTC_LOCK                                = 22,
    SSH_AGENTC_UNLOCK                              = 23,
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED       = 26,
    SSH_AGENTC_EXTENSION                           = 27,
    -- Responses
    SSH_AGENT_FAILURE                              = 5,
    SSH_AGENT_SUCCESS                              = 6,
    SSH_AGENT_EXTENSION_FAILURE                    = 28,
    SSH_AGENT_IDENTITIES_ANSWER                    = 12,
    SSH_AGENT_SIGN_RESPONSE                        = 14,
  },
  CONSTRAIN = {
    SSH_AGENT_CONSTRAIN_LIFETIME                   = 1,
    SSH_AGENT_CONSTRAIN_CONFIRM                    = 2,
    SSH_AGENT_CONSTRAIN_EXTENSION                  = 255,
  },
  SIGNATURE_FLAGS = {
    SSH_AGENT_RSA_SHA2_256                         = 2,
    SSH_AGENT_RSA_SHA2_512                         = 4,
  },

  KEY_TYPE = {
    RSA = "ssh-rsa",
    DSA = "ssh-dss",
    ECDSA_PREFIX = "ecdsa-sha2-",
    EDDSA25519 = "ssh-ed25519",
    EDDSA448 = "ssh-ed448",

    find = function (value)
      local result = findEnumValue('KEY_TYPE', value)
      if result == "ECDSA_PREFIX" then return nil end
      if result then return result end
      if value:sub(1, #SSH_AGENT_CONST.KEY_TYPE.ECDSA_PREFIX) == SSH_AGENT_CONST.KEY_TYPE.ECDSA_PREFIX then
        return 'ECDSA'
      end
    end,
  },
}

local function stringToHex(str, debug)
  local result = ""
  local format = debug and "%02x " or "%02x"
  for i = 1, #str do
    result = result .. string.format(format, str:byte(i))
  end
  if debug then
    result = result .. string.format("(%d)", #str)
  end
  return result
end

local function hexToString(hex)
  hex = string.gsub(string.gsub(hex, "%(%d+%)$", ""), "%s+", "")
  if #hex % 2 > 0 then
    log.ef("Cant parse hex '%s' because size (%d) is odd", hex, #hex)
    return nil
  end
  local result = {} -- could preallocate here
  for i = 0, #hex / 2 - 1 do
    result[i + 1] = string.char(tonumber(hex:sub(i * 2 + 1, i * 2 + 2), 16))
  end
  return table.concat(result, "")
end

local encoders = (function()
  local floor = math.floor

  local function uint32ToBytesLE(n)
      assert(n % 1 == 0 and n >= 0 and n < 2^32, "n does not fit in a uint32")
      return ("%c%c%c%c"):format(
        floor(n / 0x1000000) % 0x100, floor(n / 0x10000) % 0x100,
        floor(n / 0x100) % 0x100,     n % 0x100)
  end
  local function uint32FromBytesLE(str, offset)
    assert(#str >= offset + 4, "byte string too short")
    return str:byte(4 + offset)           + str:byte(3 + offset) * 0x100
         + str:byte(2 + offset) * 0x10000 + str:byte(1 + offset) * 0x1000000
  end

  return {
    uint8ToBytes = function (byte) return string.char(byte) end,
    uint8FromBytes = function (str, offset) return str:byte(1 + offset) end,
    uint32ToBytesLE = uint32ToBytesLE,
    uint32FromBytesLE = uint32FromBytesLE,

    stringFromBytesLE = function (data, offset)
      local size = uint32FromBytesLE(data, offset)
      return data:sub(offset + 4 + 1, offset + size + 4), size + 4
    end,
    stringToBytesLE = function (data)
      return uint32ToBytesLE(#data) .. data
    end,
  }
end)()

function prefixLengthLE(data)
  return encoders.uint32ToBytesLE(#data) .. data
end

function makePacket(type, body)
  return prefixLengthLE(string.char(type) .. (body or ""))
end

local function connectAgent(path, cbConnected)
  local TAG_SIZE, TAG_BODY = 1, 2
  local socket
  local pendingCallback
  local gotData = function (data, tag)
    -- socketLog.df("<- %s for tag %d", stringToHex(data, true), tag)
    if tag == TAG_SIZE then
      local size = encoders.uint32FromBytesLE(data, 0)
      socketLog.f(".. Expecting packet of size %d", size)
      socket:read(size, TAG_BODY)
    elseif tag == TAG_BODY then
      local responseType = encoders.uint8FromBytes(data, 0)
      socketLog.f(".. Got packet of %d bytes, response type: %s", #data, findEnumValue("TYPE", responseType, true))
      local temp = pendingCallback
      pendingCallback = nil
      temp(responseType, data:sub(2))
    else
      socketLog.e("Unknown tag %d", tag)
    end
  end
  local result = {
    write = function (data, cbGotResponse)
      socket:write(data, function ()
        if pendingCallback then
          error("Can't send, already have a pending callback")
        end
        pendingCallback = cbGotResponse
        socketLog.df("-> %s", stringToHex(data, true))
        socket:read(4, TAG_SIZE)
      end)
    end,
    disconnect = function ()
      socket:disconnect()
    end,
  }
  socket = hs.socket.new(gotData):connect(path, function ()
    cbConnected(result)
  end)
  socket:info() -- without this, doesn't work...
  if not socket:info().isConnected then
    socketLog.ef("Error connecting to '%s'", path)
    return nil
  end
  socketLog.f("Connected to %s", path)
  return result
end

-- Fields format is a table of entries in the form:
--   - `{ value, "magic" }`: Check that field equals `value` with `magic` and fail otherwise, excluded from result
--   - `{ value, "full_field_raw" }`: This field, which must be last, will contain the whole parent string (including encoded previous fields)
--   - `{ field_name, kind[, expected|sub_fields] }`: Read as `kind` and save in `field_name` (unless it starts with `_`).
--      - if the 3rd field is a table, recurse
--      - if the 3rd field isn't nil, if the parsed value doesn't match it, fail
-- If `expectIncomplete` is `true`, don't fail if there are remaining un-parsed bytes in `data`
-- Returns: error, offset, result
local function parseSSHFields(data, fields, offset, expectIncomplete, includeRaw)
  local result = includeRaw and { _raw = data } or {}
  offset = offset or 0
  for i, field in ipairs(fields) do
    local name = field[1]
    local kind = field[2]
    local expected = field[3]
    -- log.d(hs.inspect({kind = kind, expectedtype = type(expected), name = name, expected = expected, field = field}))
    local value, size
    if kind == "string" then
      value, size = encoders.stringFromBytesLE(data, offset)
      if type(expected) == "table" then
        local err
        err, _, value = parseSSHFields(value, expected, 0, false, includeRaw)
        if err then return ("Field %s: %s"):format(name, err) end
        expected = nil
      end
    elseif kind == "magic" then
      if expected ~= nil then
        error(name .. ": Field of type 'magic' uses the name as an expected value and size, and ignores the 3rd field")
      end
      local chunk = data:sub(offset, offset + #name)
      if chunk ~= name then
        return ("Expected raw '%s' but got '%s'"):format(name, chunk)
      end
      value, size = nil, #name
    elseif kind == "uint32le" then
      value = encoders.uint32FromBytesLE(data, offset)
      size = 4
    elseif kind == "full_field_raw" then
      value = data
      offset = #data
      if #fields ~= i then
        return ("At field %s: Type full_field_raw must be last"):format(name)
      end
    elseif kind == "rest" then
      value = data:sub(offset + 1)
      size = #data - offset
    else
      error("Unknown field kind: " .. hs.inspect(kind))
    end
    if expected and value ~= expected then
      return ("At field %s: Expected '%s' but got '%s'"):format(name, expected, value)
    end
    if name:sub(1, 1) ~= "_" then result[name] = value end
    if kind == "full_field_raw" then break end
    offset = offset + size
  end
  if (not expectIncomplete) and offset ~= #data then
    return ("Error, mismatch sizes. At %d/%d. Got: %s"):format(offset, #data, hs.inspect(result))
  end
  return nil, offset, result
end

local function parseSSHFieldsRequired(data, fields, offset, expectIncomplete, includeRaw)
  local err, size, result = parseSSHFields(data, fields, offset, expectIncomplete, includeRaw)
  if err then error(err) end
  return result, size
end

-- the reverse of `parseSSHFields`
local function encodeSSHFields(data, fields)
  -- log.f("encodeSSHFields(%s, %s)", hs.inspect(data), hs.inspect(fields))
  local result = ""
  for _, field in ipairs(fields) do
    local name = field[1]
    local kind = field[2]
    local expected = field[3]
    -- log.d(hs.inspect({kind = kind, expectedtype = type(expected), name = name, expected = expected, field = field}))
    if kind == "string" then
      local value = data[name]
      if type(expected) == "table" then
        value = encodeSSHFields(data[name], expected)
      end
      result = result .. encoders.stringToBytesLE(value)
    elseif kind == "magic" then
      result = result .. name
    elseif kind == "rest" then
      result = result .. data[name]
    elseif kind == "uint32le" then
      result = result .. encoders.uint32ToBytesLE(data[name])
    elseif kind == "full_field_raw" then
      return data[name]
    else
      error("Unknown field kind: " .. hs.inspect(kind))
    end
  end
  return result
end

local signatureFileFields = {
  { "SSHSIG", "magic" },
  { "ssh_version", "uint32le", 1 },
  { "pk", "string", {
      { "keyType", "string" },
      { "key", "full_field_raw" },
    },
  },
  { "ns", "string" },
  { "reserved", "string" },
  { "hash", "string" },
  { "sig", "string", {
      { "sigType", "string" },
      { "signature", "full_field_raw" },
    },
  },
}

local function readAllText(filePath)
  local file, err = io.open(filePath, "r")
  if not file then
    error("Could not open file: " .. tostring(err))
  end
  local content = file:read("*a")
  file:close()
  return content
end

-- I think the format this parses is OpenSSH and PEM
local function sshKeygenFileContentsParse(contents)
  local sep = "%-%-%-%-%-"
  local bodyPattern = ""
  bodyPattern = bodyPattern .. sep .. "BEGIN ([^-]+)" .. sep
  bodyPattern = bodyPattern .. "\n([^%z]*)\n"
  bodyPattern = bodyPattern .. sep .. "END %1" .. sep
  contents = contents:gsub("[\r]", "")
  local beginHeader, body = contents:match(bodyPattern)
  if not body then
    error(("No SSH content found in %s"):format(hs.inspect(contents)))
  end
  local headers, base64 = body:match("([^%z]-)\n\n([^%z]*)")
  if not headers then
    return beginHeader, body:gsub("[\n]", ""), nil
  end
  local headersParsed = {}
  for headerLine in string.gmatch(headers, "([^\n]+)") do
    local headerName, headerValue = headerLine:match("^([^:]-):%s*([^%z]*)$")
    table.insert(headersParsed, {headerName, headerValue})
  end
  return beginHeader, base64:gsub("[\n]", ""), headersParsed
end

local function sshKeygenReadSignatureBase64(content)
  local kind, body = sshKeygenFileContentsParse(content)
  local expectedKind = "SSH SIGNATURE"
  if kind ~= expectedKind then
    error(("Error parsing %s, expected %s but got %s"):format(filePath, hs.inspect(expectedKind), hs.inspect(kind)))
  end
  return hs.base64.decode(body)
end

local function sshKeygenReadSignatureFileBase64(filePath)
  return sshKeygenReadSignatureBase64(readAllText(filePath))
end

local function sshKeygenReadPrivateKey(content)
  local kind, body, headers = sshKeygenFileContentsParse(content)
  local expectedPattern = " PRIVATE KEY$"
  if not kind:match(expectedPattern) then
    error(("Expected to match %s but got %s in: %s"):format(content, hs.inspect(expectedPattern), hs.inspect(kind), hs.inspect(content)))
  end
  return { kind = kind:gsub(expectedPattern, ""), body = hs.base64.decode(body), headers = headers }
end

local function sshKeygenReadPrivateKeyFile(filePath)
  return sshKeygenReadPrivateKey(readAllText(filePath))
end

--- SSHSignatures:sshKeygenReadSignature(contents)
--- Function
---  Parses the output of `ssh-keygen -Y sign`
---
--- Parameters:
---  * `contents`: String with `ssh-keygen` signature format
---
--- Returns:
---  * A table of the format (values are examples):
---    ```lua
---    { hash = "sha512",
---      ns = "file",
---      pk =  { keyType = "ssh-ed25519", key = string },
---      sig = { sigType = "ssh-ed25519", signature = string },
---      reserved = "",
---      ssh_version = 1 }
---    ```
function obj:sshKeygenReadSignature(contents)
  local signature = sshKeygenReadSignatureBase64(contents)
  local parsed = parseSSHFieldsRequired(signature, signatureFileFields)
  if signature ~= encodeSSHFields(parsed, signatureFileFields) then error("Mismatch when regenerating parsed signature") end
  return parsed
end

local function sshAgentSendRequest(requestPacket, expectedResponseType, cbResponse)
  connectAgent(obj.socketPath, function (socket)
    socket.write(requestPacket, function (responseType, response)
      socket.disconnect()
      if expectedResponseType and expectedResponseType ~= responseType then
        local typeReceived = findEnumValue("TYPE", responseType, true)
        local typeExpected = findEnumValue("TYPE", expectedResponseType, true)
        error(("Expected response %s but got %s"):format(typeExpected, typeReceived))
      end
      cbResponse(responseType, response)
    end)
  end)
end

--- SSHSignatures:sshAgentListIdentities(cbResponse)
--- Function
---  Retreive a list of loaded identities/public keys from `ssh-agent`
---
--- Parameters:
---  * `cbResponse`: A callback function that will receive the list of identities as first argument
---
--- Returns:
---  * `SSHSignatures`
---
--- Notes:
---  * `cbResponse` will be called with a table of keys, each in the format:
---    ```lua
---    { comment = string,
---      key = string,
---      keyType = "ssh-rsa" -- example key type
---    }
---    ```
function obj:sshAgentListIdentities(cbResponse)
  local requestPacket = makePacket(SSH_AGENT_CONST.TYPE.SSH_AGENTC_REQUEST_IDENTITIES)
  sshAgentSendRequest(requestPacket, SSH_AGENT_CONST.TYPE.SSH_AGENT_IDENTITIES_ANSWER, function (responseType, response)
    local numKeys = encoders.uint32FromBytesLE(response, 0)
    log.f("Got %d key(s) in %d bytes", numKeys, #response)
    local offset = 4
    local keys = {}
    for i = 1, numKeys do
      local keyAndComment, endOffset = parseSSHFieldsRequired(response, {
        { "key", "string", {
          { "keyType", "string" },
          -- [RFC4253] for `ssh-rsa` and `ssh-dss` keys
          -- [RFC5656] for `ecdsa-sha2-*` keys
          -- [RFC8709] for `ssh-ed25519` and `ssh-ed448` keys.
          { "key", "full_field_raw" },
        } },
        { "comment", "string" },
      }, offset, true, false)
      keyAndComment.key.comment = keyAndComment.comment
      log.df("  - Key %d key is %d bytes (data is %d)", i, endOffset - offset, #(keyAndComment.key))
      offset = endOffset
      table.insert(keys, keyAndComment.key)
    end
    cbResponse(keys)
  end)
  return obj
end

local function getKeyFromArgument(key)
  if type(key) == "string" then
    local keyType = encoders.stringFromBytesLE(key, 0)
    return { key = key, keyType = keyType }
  end
  return key
end

local function sshAgentMakeSignRequest(data, key, ns)
  local reserved = ""
  local dataHash = hs.hash.new("SHA512"):append(data):finish():value(true) -- hs.hash.types.SHA512))
  local payloadToSign = "SSHSIG" ..
                        encoders.stringToBytesLE(ns) ..
                        encoders.stringToBytesLE(reserved) ..
                        encoders.stringToBytesLE("sha512") .. -- Later handle the flag maybe
                        encoders.stringToBytesLE(dataHash)
  local signRequestBody = encoders.stringToBytesLE(key.key) ..
                          encoders.stringToBytesLE(payloadToSign) ..
                          encoders.uint32ToBytesLE(key.keyType == "ssh-rsa" and SSH_AGENT_CONST.SIGNATURE_FLAGS.SSH_AGENT_RSA_SHA2_512 or 0)
  return makePacket(SSH_AGENT_CONST.TYPE.SSH_AGENTC_SIGN_REQUEST, signRequestBody)
end


--- SSHSignatures:sshAgentSign(data, key, ns, cbResponse)
--- Function
---  Request `ssh-agent` sign `data` with the private key corresponding to `pk`
---
--- Parameters:
---  * `data`: A string with the data to sign
---  * `key`: The public key to use to find the key to sign with. Either a string or a value from `SSHSignatures:sshAgentListIdentities`
---  * `ns`: A string with the namespace included in the signed data. Usually `"file"` or `"email"` or `"custom@your.domain"`
---  * `cbResponse`: A callback function that will receive the signature as first argument
---
--- Returns:
---  * `SSHSignatures`
---
--- Notes:
---  * `cbResponse` will be called with the signature in the format:
---    ```lua
---    { signature = string,
---      keyType = "ssh-rsa" -- example key type, extracted from the `signature` field, just informative
---    }
---    ```
function obj:sshAgentSign(data, key, ns, cbResponse)
  key = getKeyFromArgument(key)
  local requestPacket = sshAgentMakeSignRequest(data, key, ns)
  sshAgentSendRequest(requestPacket, SSH_AGENT_CONST.TYPE.SSH_AGENT_SIGN_RESPONSE, function (responseType, response)
    local signature, _endOffset = parseSSHFieldsRequired(response, {
      { "signatureReponse", "string", {
        { "keyType", "string" },
        { "signature", "full_field_raw" },
      } },
    })
    cbResponse(signature.signatureReponse)
  end)
  return obj
end

--- SSHSignatures:sshAgentLockUnlock(lock, passphrase, cbResponse)
--- Function
---  Request `ssh-agent` to lock or unlock with the given `passphrase`. When locked all other requests are denied.
---
--- Parameters:
---  * `lock`: `true` to lock the agent, `false` to unlock
---  * `passphrase`: string that when unlocking, must match the one provided when locking
---  * `cbResponse`: A callback function that will receive wether the operation succeded as first argument
---
--- Returns:
---  * `SSHSignatures`
---
--- Notes:
---  ```lua
---  -- Lock
---  spoon.SSHSignatures:sshAgentLockUnlock(true, "passphrase", function (succeded)
---    assert(succeded)
---    spoon.SSHSignatures:sshAgentListIdentities(function (keys)
---      print(hs.inspect(keys)) -- {}
---
---      -- Unlock
---      spoon.SSHSignatures:sshAgentLockUnlock(false, "passphrase", function (succeded)
---        assert(succeded)
---
---        spoon.SSHSignatures:sshAgentListIdentities(function (keys)
---          print(hs.inspect(keys)) -- { key1, key2, ... }
---        end)
---      end)
---    end)
---  end)
---  ```
function obj:sshAgentLockUnlock(lock, passphrase, cbResponse)
  local requestType = lock and SSH_AGENT_CONST.TYPE.SSH_AGENTC_LOCK or SSH_AGENT_CONST.TYPE.SSH_AGENTC_UNLOCK
  local requestPacket = makePacket(requestType, encoders.stringToBytesLE(passphrase))
  sshAgentSendRequest(requestPacket, nil, function (responseType, response)
    cbResponse(responseType == SSH_AGENT_CONST.TYPE.SSH_AGENT_SUCCESS)
  end)
end

-- This function runs the equivalent of this command (except the redir, output is just
-- captured to a string):
--     echo -n hi | ssh-keygen -Y sign -n file -f $keyFile > /tmp/hi.sshsig
-- To test the result in the shell, this command can be used
--     echo -n hi | ssh-keygen -Y check-novalidate -n file -f $keyFile -s /tmp/hi.sshsig
local function runSSHKeygenSign(keyFile, ns, data, cbResponse)
  local command = { "ssh-keygen", "-Y", "sign", "-n", ns, "-f", keyFile }
  log.df("Executing %s", hs.inspect(command))
  local task = hs.task.new("/usr/bin/env", function (exitCode, stdOut, stdErr)
    log.df("Execution: %s", hs.inspect({exitCode = exitCode, stdOut = stdOut, stdErr = stdErr}))
    if exitCode ~= 0 then
      error("Error running " .. hs.inspect(command) .. ", exit code " .. exitCode .. ":\n" .. stdErr)
    end
    local signature = sshKeygenReadSignatureBase64(stdOut)
    local parsed = parseSSHFieldsRequired(signature, signatureFileFields)
    cbResponse(parsed, signature)
  end, command)
  task:setInput(data)
  if not task:start() then error("Error starting process") end
end

-- For a given keyFile, run `ssh-keygen` to sign `data`, then
-- list keys in the `ssh-agent`, find the same one, sign the
-- same data, and it `error()` if the signatures don't match
local function compareSSHKeygenAndAgentSigning(keyFile, ns, data, cbDone)
  log.f("Running test with key file %s on data %s", keyFile, hs.inspect(data))
  runSSHKeygenSign(keyFile, ns, data, function (keygenSignatureParsed, keygenSignature)
    log.f("ssh-keygen signature: %s (%d bytes)", hs.inspect(keygenSignature), #keygenSignature)
    log.f("ssh-keygen signature parsed: %s", hs.inspect(keygenSignatureParsed))

    obj:sshAgentListIdentities(function (keys)
      local foundKey = false
      for _, key in ipairs(keys) do
        if key.key == keygenSignatureParsed.pk.key then
          foundKey = true
          break
        end
      end
      if not foundKey then
        error("Key " .. keyFile .. " not found in ssh-agent")
      end

      obj:sshAgentSign(data, keygenSignatureParsed.pk.key, ns, function (response)
        if keygenSignatureParsed.sig.signature ~= response.signature then
          error("Signatures do not match")
        end
        if cbDone then cbDone() end
      end)
    end)
  end)
end

local function testSigning()
  compareSSHKeygenAndAgentSigning(os.getenv("HOME") .. "/.ssh/id_ed25519", "file", "hi")
  compareSSHKeygenAndAgentSigning(os.getenv("HOME") .. "/.ssh/id_rsa", "file", "hi")
end
-- testSigning()


local function testLocking()
  obj:sshAgentLockUnlock(true, "passphrase", function (success)
    log.f("Locked agent result: %s", tostring(success))
    obj:sshAgentLockUnlock(false, "wrong passphrase", function (success)
      log.f("Unlock agent with wrong passphrase result: %s", tostring(success))
      obj:sshAgentLockUnlock(false, "passphrase", function (success)
        log.f("Unlock agent with right passphrase result: %s", tostring(success))
      end)
    end)
  end)
end
-- testLocking()

return obj
