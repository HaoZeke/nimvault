## Secret-scan rules and wrap globs, without a GPG key. These used to be PCRE.

import std/strutils
import nimvault/commands
import nimvault/dek

proc hit(line, rule: string) =
  doAssert matchSecretRule(line) == rule, line & " -> " & matchSecretRule(line)

proc miss(line: string) =
  doAssert matchSecretRule(line) == "", line

block secretRules:
  hit("sk-ant-" & repeat('A', 24), "anthropic-api-key")
  hit("xx sk-ant-" & repeat('b', 30) & " yy", "anthropic-api-key")
  miss("sk-ant-" & repeat('A', 23))
  hit("sk-" & repeat('A', 20), "openai-api-key")
  hit("sk-" & repeat('z', 40), "openai-api-key")
  miss("sk-" & repeat('A', 19))
  # The hyphen keeps an Anthropic key off the generic sk- rule.
  hit("sk-ant-" & repeat('C', 24), "anthropic-api-key")
  hit("ctx7sk-" & repeat('a', 20), "context7-api-key")
  hit("ctx7sk-" & repeat('-', 20), "context7-api-key")
  # Uppercase is not context7's alphabet, and `sk-` plus those letters is an
  # OpenAI key. A short body matches neither.
  hit("ctx7sk-" & repeat('A', 20), "openai-api-key")
  miss("ctx7sk-" & repeat('a', 19))
  hit("ghp_" & repeat('a', 20), "github-pat")
  hit("gho_" & repeat('Z', 20), "github-pat")
  hit("ghu_" & repeat('0', 20), "github-pat")
  hit("ghs_" & repeat('a', 20), "github-pat")
  hit("ghr_" & repeat('a', 20), "github-pat")
  hit("github_pat_" & repeat('a', 10) & repeat('_', 10), "github-pat")
  miss("ghp_" & repeat('a', 19))
  miss("ghx_" & repeat('a', 20))
  miss("ghp_" & repeat('a', 19) & "_" & repeat('a', 5))
  hit("glpat-" & repeat('a', 20), "gitlab-pat")
  miss("glpat-" & repeat('a', 19))
  hit("xoxb-" & repeat('a', 10), "slack-token")
  hit("xoxa-" & repeat('-', 10), "slack-token")
  hit("xoxp-" & repeat('Z', 12), "slack-token")
  hit("xoxr-" & repeat('a', 10), "slack-token")
  hit("xoxs-" & repeat('a', 10), "slack-token")
  miss("xoxc-" & repeat('a', 10))
  miss("xoxb-" & repeat('a', 9))
  hit("AKIA" & repeat('A', 16), "aws-access-key")
  hit("ASIA0123456789ABCDEF", "aws-access-key")
  hit("xx ASIA" & repeat('Z', 20), "aws-access-key")
  miss("AKIA" & repeat('A', 15))
  miss("AKIA" & repeat('a', 16))
  miss("AKIA" & repeat('A', 15) & "a" & repeat('A', 5))
  hit("-----BEGIN PRIVATE KEY-----", "ssh-private-key")
  hit("-----BEGIN RSA PRIVATE KEY-----", "ssh-private-key")
  hit("-----BEGIN OPENSSH PRIVATE KEY-----", "ssh-private-key")
  hit("-----BEGIN EC PRIVATE KEY-----", "ssh-private-key")
  hit("-----BEGIN  PRIVATE KEY-----", "ssh-private-key")
  miss("-----BEGIN private key-----")
  miss("-----BEGIN RSA PRIVATE KEY")
  # First rule on the line wins.
  hit("sk-" & repeat('A', 20) & " -----BEGIN PRIVATE KEY-----", "openai-api-key")
  echo "PASS: secret rules match the old patterns"

block stagedNames:
  doAssert isUnsealStageName(".nimvault-0123456789abcdef.tmp")
  doAssert not isUnsealStageName(".nimvault-0123456789ABCDEF.tmp")
  doAssert not isUnsealStageName(".nimvault-mv-0123456789abcdef.tmp")
  doAssert not isUnsealStageName(".nimvault-0123456789abcde.tmp")
  doAssert not isUnsealStageName(".nimvault-0123456789abcdefg.tmp")
  doAssert not isUnsealStageName(".nimvault-0123456789abcdeg.tmp")
  echo "PASS: staged plaintext names"

block globs:
  doAssert matchGlob("**/mine.txt", "mine.txt")
  doAssert matchGlob("**/mine.txt", "dir/mine.txt")
  doAssert matchGlob("**/mine.txt", "a/b/mine.txt")
  doAssert not matchGlob("**/mine.txt", "mine.txt.bak")
  doAssert not matchGlob("**/mine.txt", "notmine.txt")
  doAssert matchGlob("~/.ssh/**", "~/.ssh/id_ed25519")
  doAssert matchGlob("~/.ssh/**", "~/.ssh/a/b")
  doAssert not matchGlob("~/.ssh/**", "~/.ssh")
  doAssert matchGlob("~/.claude/", "~/.claude/settings.json")
  doAssert matchGlob("~/.claude/", "~/.claude/a/b")
  doAssert not matchGlob("~/.claude/", "~/.other/settings.json")
  doAssert matchGlob("~/x/*", "~/x/one")
  doAssert not matchGlob("~/x/*", "~/x/deep/one")
  doAssert matchGlob("file?.txt", "file?.txt")
  doAssert not matchGlob("file?.txt", "fileX.txt")
  doAssert not matchGlob("file?.txt", "fil.txt")
  doAssert matchGlob("**", "anything")
  doAssert matchGlob("**", "")
  doAssert not matchGlob("", "x")
  doAssert matchGlob("*.txt", "a.txt")
  doAssert not matchGlob("*.txt", "dir/a.txt")
  doAssert matchGlob("a/**/b", "a/b")
  doAssert matchGlob("a/**/b", "a/x/y/b")
  doAssert not matchGlob("a/**/b", "ab")
  doAssert matchGlob("foo/", "foo/bar")
  doAssert matchGlob("foo/", "foo/a/b")
  doAssert not matchGlob("foo/", "foo")
  doAssert matchGlob(".ssh/**", ".ssh/id_ed25519")
  echo "PASS: wrap globs"
