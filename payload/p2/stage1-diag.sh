#!/bin/bash
# stage1-diag - uep2 boot diagnostics. Runs as root (60s window), writes
# everything to the stick's p2 ($P2) for offline pickup.
LOG="$P2/uep2-diag.log"
{
  echo "=== uep2-diag $(date) uid=$(id -u) ==="
  echo "--- /proc/partitions ---"; cat /proc/partitions
  echo "--- partition headers (uImage magic 27051956?) ---"
  for p in 11 12 13 14 15 16 17 20 22 23 24; do
    m=$(dd if=/dev/mmcblk0p$p bs=64 count=1 2>/dev/null | od -An -tx4 -N16 | tr -d ' \n')
    echo "p$p: $m"
  done
  echo "--- full dumps ---"
  for p in 12 13 14 15 16 17 20 24; do
    dd if=/dev/mmcblk0p$p of="$P2/part-p$p.bin" bs=1M 2>/dev/null &
  done
  wait
  ls -la "$P2"/part-* 2>/dev/null
  echo "--- kallsyms/iomem/dmesg ---"
  grep -iE 'uep|sfd' /proc/kallsyms 2>&1 | head -10
  cat /proc/sys/kernel/kptr_restrict 2>/dev/null
  dmesg 2>/dev/null | grep -iE 'uep|sfd|sign' | tail -20
} > "$LOG" 2>&1

# exec test + flag re-read at the end of the window (after stage1's work)
(
  sleep 20
  {
      echo "=== exectest ==="
    /opt/bin/dropbearmulti dropbearkey -t ed25519 -f "$P2/testkey" 2>&1; echo "rc=$?"
    dmesg 2>/dev/null | grep -iE 'uep|sfd|sign|not permitted' | tail -15
  } >> "$LOG" 2>&1
) &
