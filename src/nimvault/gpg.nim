## GPG encryption/decryption and recipient resolution.

import std/[os, osproc, strutils, strformat]

type
  GpgConfig* = object
    recipient*: string
    root*: string  ## When non-empty, paths are relative to this dir (not ~/...)

proc parseVaultConfig(configFile: string): tuple[recipient, root: string] =
  ## Parse .vault/config for recipient and root keys.
  if not fileExists(configFile):
    return ("", "")
  for line in lines(configFile):
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('=', maxsplit = 1)
    if parts.len == 2:
      let key = parts[0].strip()
      let val = parts[1].strip()
      if val.len > 0:
        case key
        of "recipient": result.recipient = val
        of "root": result.root = val

proc resolveRecipient*(cli, env, configRecipient: string): string =
  ## 3-tier recipient lookup:
  ## 1. CLI --recipient flag
  ## 2. NIMVAULT_GPG_RECIPIENT env var
  ## 3. value from .vault/config
  if cli.len > 0:
    return cli
  let envVal = getEnv(env)
  if envVal.len > 0:
    return envVal
  if configRecipient.len > 0:
    return configRecipient
  stderr.writeLine "FATAL: no GPG recipient found"
  stderr.writeLine "  Set via --recipient, NIMVAULT_GPG_RECIPIENT env, or .vault/config"
  quit 1

proc initGpgConfig*(cliRecipient: string, repo: string): GpgConfig =
  ## Build a GpgConfig by resolving recipient and root from the 3-tier chain.
  let configPath = repo / ".vault" / "config"
  let (cfgRecipient, cfgRoot) = parseVaultConfig(configPath)
  var root = cfgRoot
  if root == "repo":
    root = repo
  elif root.len > 0 and not root.isAbsolute:
    root = repo / root
  result = GpgConfig(
    recipient: resolveRecipient(cliRecipient, "NIMVAULT_GPG_RECIPIENT", cfgRecipient),
    root: root,
  )

proc run(cmd: string, workDir = ""): tuple[output: string, exitCode: int] =
  execCmdEx(cmd, workingDir = if workDir.len > 0: workDir else: getCurrentDir())

proc runOrDie(cmd: string, workDir = ""): string =
  let (output, code) = run(cmd, workDir)
  if code != 0:
    stderr.writeLine &"FATAL: command failed (exit {code}):\n  {cmd}\n{output}"
    quit 1
  result = output.strip()

proc gpgEncrypt*(cfg: GpgConfig, inPath, outPath: string) =
  ## Encrypt a file using GPG with the configured recipient.
  discard runOrDie(&"gpg --batch --yes --quiet --trust-model always " &
    &"-e -r {cfg.recipient} --set-filename \"\" -o {outPath.quoteShell} {inPath.quoteShell}")

proc gpgDecrypt*(inPath, outPath: string) =
  ## Decrypt a GPG-encrypted file to a target path.
  discard runOrDie(&"gpg --batch --yes --quiet -d -o {outPath.quoteShell} {inPath.quoteShell}")

proc gpgDecryptToString*(inPath: string): string =
  ## Decrypt a GPG-encrypted file and return contents as a string.
  runOrDie(&"gpg --batch --yes --quiet -d {inPath.quoteShell}")

proc sha256sum*(path: string): string =
  ## Returns hex SHA-256 digest of a file.
  let res = runOrDie(&"sha256sum {path.quoteShell}")
  result = res.split(' ')[0]
