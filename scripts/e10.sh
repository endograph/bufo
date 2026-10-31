#!/bin/zsh -f
# E10 (PLAN.md, Experiments): an intruder's comparison of the SSH keys in ~/.ssh, modeled on
# published honeytoken fingerprinting. It uses no key. Each private key gets a point for every
# readable way it differs from most of its neighbours, and the highest scores are its pick. Run it
# on a bait laptop as the account holding the bait; a decoy should be picked no more often than
# chance. Prints one line per key: score, name, and the reasons.
set -u
setopt null_glob
cd ~/.ssh || exit 1
config=(config ${(f)"$(awk 'tolower($1) == "include" { for (i = 2; i <= NF; i++) print $i }' config 2>/dev/null)"})
seen=$(cat ~/.zsh_history ~/.bash_history 2>/dev/null | tail -n 20000)
agent=$(for s in "${SSH_AUTH_SOCK:-}" agent/*(=); do [[ -S $s ]] && SSH_AUTH_SOCK=$s ssh-add -L 2>/dev/null; done)

typeset -A pass pub comment mode modified created changed named known mentioned loaded
keys=()
for f in *(.); do
  [[ $(head -c 40 $f 2>/dev/null) == -----BEGIN*PRIVATE\ KEY-----* ]] || continue
  keys+=$f
  ssh-keygen -y -P '' -f $f >/dev/null 2>&1 && pass[$f]=no || pass[$f]=yes
  [[ -f $f.pub ]] && pub[$f]=yes || pub[$f]=no
  comment[$f]=$(cut -d' ' -f3- $f.pub 2>/dev/null | sed -E 's/[0-9]+/N/g')
  mode[$f]=$(stat -f %Lp $f)
  modified[$f]=$(stat -f %m $f); created[$f]=$(stat -f %B $f); changed[$f]=$(stat -f %c $f)
  # The Host entries whose IdentityFile names this key.
  hosts=$(awk -v k="$f" 'tolower($1) == "host" { h = $2 } tolower($1) == "identityfile" && $2 ~ ("/" k "$") { print h }' $config 2>/dev/null)
  named[$f]=$([[ -n $hosts ]] && echo yes || echo no)
  known[$f]=no; mentioned[$f]=no
  for h in ${(f)hosts}; do
    lookup=$(ssh -G $h 2>/dev/null | awk '$1 == "hostkeyalias" { a = $2 } $1 == "hostname" { n = $2 } END { print (a != "" ? a : n) }')
    ssh-keygen -F "$lookup" -f known_hosts >/dev/null 2>&1 && known[$f]=yes
    [[ $seen == *"$h"* ]] && mentioned[$f]=yes
  done
  blob=$(ssh-keygen -y -P '' -f $f 2>/dev/null | cut -d' ' -f2)
  [[ -n $blob && $agent == *$blob* ]] && loaded[$f]=yes || loaded[$f]=no
done
(( ${#keys} >= 2 )) || { print "fewer than two keys to compare"; exit 0; }

# A point when a key's value is shared by fewer than half the keys.
typeset -A score why
odd() {
  local -A count; local k v
  for k in $keys; do v=${${(P)1}[$k]}; count[$v]=$(( ${count[$v]:-0} + 1 )); done
  for k in $keys; do
    v=${${(P)1}[$k]}
    if (( count[$v] * 2 < ${#keys} )); then score[$k]=$(( ${score[$k]:-0} + 1 )); why[$k]+="$1=$v "; fi
  done
}
for feature in pass pub comment mode named known mentioned loaded; do odd $feature; done
# Times: the newest inode change and creation, and a modification time far behind the inode change.
newest() {
  local k top=0
  for k in $keys; do (( ${${(P)1}[$k]} > top )) && top=${${(P)1}[$k]}; done
  for k in $keys; do
    (( ${${(P)1}[$k]} == top )) && { score[$k]=$(( ${score[$k]:-0} + 1 )); why[$k]+="newest-$1 "; }
  done
}
newest changed; newest created
for k in $keys; do
  (( changed[$k] - modified[$k] > 86400 )) && { score[$k]=$(( ${score[$k]:-0} + 1 )); why[$k]+="backdated "; }
done
for k in $keys; do print "${score[$k]:-0} $k ${why[$k]:-}"; done | sort -rn
