#+TITLE: nimvault
#+OPTIONS: toc:nil num:nil

GPG-encrypted opaque-blob vault with hidden filenames.

* About

nimvault stores sensitive files with opaque filenames and encrypted contents
using GPG. Both filenames and contents are hidden from git history. Only random
hex blob names and a GPG-encrypted manifest are committed.

* Install

#+BEGIN_SRC bash
nimble install nimvault
#+END_SRC

Or build from source:

#+BEGIN_SRC bash
git clone https://github.com/HaoZeke/nimvault.git
cd nimvault
nimble build -y
#+END_SRC

* Usage

#+BEGIN_SRC bash
# Configure recipient in your git repo
mkdir -p .vault
echo "recipient = YOUR_KEY_ID" > .vault/config

# Add files, seal, commit
nimvault add ~/.secret/api_key.txt
nimvault seal
git add .vault/ && git commit -m "vault: add secrets"

# Restore on another machine
nimvault unseal
nimvault status
#+END_SRC

* Documentation

Full docs at [[https://nimvault.rgoswami.me]].

* License

MIT. See [[file:LICENSE][LICENSE]].
