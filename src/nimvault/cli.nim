## CLI dispatch for nimvault.
##
## Usage: nimvault [--recipient KEY] <command> [args]

import std/[os, osproc, strutils, strformat, parseopt]
import ./gpg, ./commands

const Version = "0.1.0"

proc repoRoot(): string =
  let (output, code) = execCmdEx("git rev-parse --show-toplevel")
  if code != 0:
    stderr.writeLine "FATAL: not inside a git repository"
    quit 1
  result = output.strip()

proc usage() =
  echo """nimvault -- GPG-encrypted opaque-blob vault with hidden filenames

Usage: nimvault [--recipient KEY] <command> [args]

Commands:
  seal          Encrypt all vault entries from their plaintext locations
  unseal        Decrypt all vault entries to their target locations
  add <path>    Add a file to the vault
  rm <path>     Remove a file from the vault
  mv <old> <new>  Move/rename a vault entry
  list          List all vault entries
  status        Show sync status of all entries

Options:
  --recipient KEY   GPG recipient key (overrides env/config)
  --help            Show this help
  --version         Show version"""

proc main*() =
  var
    cliRecipient = ""
    positional: seq[string] = @[]

  var p = initOptParser(commandLineParams())
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdLongOption, cmdShortOption:
      case p.key
      of "recipient": cliRecipient = p.val
      of "help", "h":
        usage()
        quit 0
      of "version", "v":
        echo &"nimvault {Version}"
        quit 0
      else:
        stderr.writeLine &"unknown option: --{p.key}"
        quit 1
    of cmdArgument:
      positional.add(p.key)

  if positional.len == 0:
    usage()
    quit 1

  let repo = repoRoot()
  let cfg = initGpgConfig(cliRecipient, repo)
  let cmd = positional[0]

  case cmd
  of "seal":
    seal(repo, cfg)
  of "unseal":
    unseal(repo, cfg)
  of "add":
    if positional.len < 2:
      stderr.writeLine "usage: nimvault add <path>"
      quit 1
    add(repo, positional[1], cfg)
  of "rm":
    if positional.len < 2:
      stderr.writeLine "usage: nimvault rm <path>"
      quit 1
    remove(repo, positional[1], cfg)
  of "mv":
    if positional.len < 3:
      stderr.writeLine "usage: nimvault mv <old-path> <new-path>"
      quit 1
    move(repo, positional[1], positional[2], cfg)
  of "list":
    list(repo, cfg)
  of "status":
    status(repo, cfg)
  else:
    stderr.writeLine &"unknown command: {cmd}"
    quit 1
