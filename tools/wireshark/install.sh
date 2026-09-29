#!/usr/bin/env bash
# Install the LoRaSpy Wireshark integration for the current user:
#   - extcap interface "LoRaSpy (RTL-SDR, shared)"  (symlink)
#   - Lua dissectors for Meshtastic, MeshCore and the LoRaSpy post-dissector (symlink)
#   - protobuf search paths so Meshtastic payloads decode (Meshtastic .protos + /usr/include)
# Symlinks point back into this checkout, so later updates apply without reinstalling.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
folders="$(tshark -G folders 2>/dev/null)"
extcap_dir="$(awk -F'\t' '/^Personal Extcap path:/ {print $2}' <<<"$folders")"
lua_dir="$(awk -F'\t' '/^Personal Lua Plugins:/ {print $2}' <<<"$folders")"
conf_dir="$(awk -F'\t' '/^Personal configuration:/ {print $2}' <<<"$folders")"
: "${extcap_dir:=$HOME/.local/lib/wireshark/extcap}"
: "${lua_dir:=$HOME/.local/lib/wireshark/plugins}"
: "${conf_dir:=$HOME/.config/wireshark}"

mkdir -p "$extcap_dir" "$lua_dir" "$conf_dir"
# earlier installs (the project used to be called sdr-monitor): two copies of the Lua
# dissector would clash ("two protocols with the same description")
for old in "$extcap_dir/sdrmon_extcap.py" "$lua_dir/sdrmon.lua"; do
    if [ -L "$old" ]; then rm -f "$old" && echo "removed old $old"; fi
done
chmod +x "$HERE/loraspy_extcap.py"
ln -sfn "$HERE/loraspy_extcap.py" "$extcap_dir/loraspy_extcap.py"
ln -sfn "$HERE/loraspy.lua" "$lua_dir/loraspy.lua"
echo "extcap : $extcap_dir/loraspy_extcap.py"
echo "lua    : $lua_dir/loraspy.lua"

# protobuf search paths (UAT file); add our entries only if missing
uat="$conf_dir/protobuf_search_paths"
touch "$uat"
# drop entries of our protobufs folder from an earlier location of this checkout
grep -v '/tools/wireshark/protobufs",' "$uat" > "$uat.tmp" || true
grep -F "\"$HERE/protobufs\"" "$uat" >> "$uat.tmp" || true
mv "$uat.tmp" "$uat"
for entry in "\"$HERE/protobufs\",\"TRUE\"" "\"/usr/include\",\"FALSE\""; do
    grep -qxF "$entry" "$uat" || echo "$entry" >> "$uat"
done
echo "protobuf search paths: $uat"
echo
echo "Restart Wireshark, then capture on 'LoRaSpy (RTL-SDR, shared)'."
echo "It attaches to a running LoRaSpy or opens the SDR itself; its options also offer"
echo "receiving loraspy.py --wireshark-feed over UDP (tab 'Remote (UDP)')."
