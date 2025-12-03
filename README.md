# SSHSignatures Spoon

A [Hammerspoon](https://www.hammerspoon.org/) spoon to interact with `ssh-agent`. It allows you to list public keys, sign data, and lock/unlock the agent.

## Installation

1.  Download the latest release from the [releases page](https://github.com/ddlsmurf/SSHSignatures.spoon/releases/latest).
2.  Unzip the downloaded file.
3.  Double-click the `SSHSignatures.spoon` file to install it.

## Usage

### List keys and sign data

```lua
hs.loadSpoon("SSHSignatures")

spoon.SSHSignatures:sshAgentListIdentities(function (keys)
  print(hs.inspect(keys))

  spoon.SSHSignatures:sshAgentSign("some data to sign", keys[1], "file", function (signature)
    print(hs.inspect(signature))
  end)
end)
```

### Lock and unlock the agent

```lua
hs.loadSpoon("SSHSignatures")

-- Lock
spoon.SSHSignatures:sshAgentLockUnlock(true, "passphrase", function (succeded)
  assert(succeded)
  spoon.SSHSignatures:sshAgentListIdentities(function (keys)
    print(hs.inspect(keys)) -- {}

    -- Unlock
    spoon.SSHSignatures:sshAgentLockUnlock(false, "passphrase", function (succeded)
      assert(succeded)

      spoon.SSHSignatures:sshAgentListIdentities(function (keys)
        print(hs.inspect(keys)) -- { key1, key2, ... }
      end)
    end)
  end)
end)
```
