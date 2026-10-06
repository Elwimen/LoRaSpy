# Running LoRaSpy on Windows (WSL2)

LoRaSpy is built on GNU Radio, gr-osmosdr and a source build of
[gr-lora_sdr](https://github.com/tapparelj/gr-lora_sdr) — a native Linux SDR stack. The
supported way to run it on Windows is **WSL2** (Windows Subsystem for Linux), which is a real
Linux kernel inside Windows: the Linux setup works unchanged, the RTL-SDR passes through with
`usbipd-win`, and the Qt GUI runs through WSLg.

> **Why not Wine?** Wine runs Windows `.exe` files on Linux; it is not a Linux-inside-Windows
> environment. There is no Wine build of GNU Radio / gr-osmosdr / gr-lora_sdr, and RTL-SDR USB
> access does not work through Wine. WSL2 is the right tool.

This guide was written from the code and standard WSL practice. Package names and GNU Radio
versions vary between Ubuntu releases — if one is not found, search for the closest match
(`apt search <name>`). Steps that depend on your Windows/WSL version are flagged.

---

## 1. Requirements

- **Windows 11**, or **Windows 10 22H2** (build 19045+). WSLg (the GUI bridge) and USB passthrough
  need a recent WSL. [Unverified on older builds — update first.]
- Admin PowerShell for the WSL and USB steps.

## 2. Install WSL2 + Ubuntu

In an **admin PowerShell**:

```powershell
wsl --install            # installs WSL2 + Ubuntu (reboot if prompted)
wsl --update             # pulls the latest WSL kernel (needed for GUI + USB)
wsl --version            # confirm "WSL version: 2.x" and a recent "Kernel version"
```

Launch **Ubuntu** from the Start menu and create your Linux user when asked. Everything below
runs **inside the Ubuntu (WSL) shell** unless it says PowerShell.

## 3. (Recommended) enable systemd in WSL

systemd gives you working `udev` rules (so the RTL-SDR is usable without `sudo`) and a
`$XDG_RUNTIME_DIR` for the SDR-sharing socket. Edit `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

Then from **PowerShell**: `wsl --shutdown`, and reopen Ubuntu.

> Without systemd LoRaSpy still works — the sharing socket falls back to `/tmp/loraspy-<uid>.sock`
> — but you may have to run SDR commands with `sudo` (see Troubleshooting).

## 4. Install the dependencies (Ubuntu)

```bash
sudo apt update
# GNU Radio 3.10, gr-osmosdr, RTL-SDR tools, and the gr-lora_sdr build toolchain:
sudo apt install -y \
    gnuradio gnuradio-dev gr-osmosdr rtl-sdr librtlsdr-dev \
    cmake g++ git pybind11-dev libboost-all-dev libspdlog-dev \
    liblog4cpp5-dev libfftw3-dev python3-pip python3-numpy python3-scipy
# volk headers: name differs by release — try one of these:
sudo apt install -y libvolk2-dev || sudo apt install -y libvolk-dev
# Qt binding for the --gui, and Python packages not in apt:
sudo apt install -y python3-pyqt5 python3-pyqtgraph
pip install --user meshtastic cryptography textual
```

> **PEP 668 (Ubuntu 23.04+):** if `pip install --user` is refused with an
> "externally-managed-environment" error, add `--break-system-packages`, or use a venv created
> with `python3 -m venv --system-site-packages .venv` (so it can still import the apt-installed
> `gnuradio`/`osmosdr`) and `source .venv/bin/activate` before the pip + run steps.

## 5. Get LoRaSpy and build gr-lora_sdr

```bash
git clone <your LoRaSpy repo URL> ~/loraspy    # or copy the folder into WSL
cd ~/loraspy
./scripts/build_gr_lora_sdr.sh                  # builds into ./deps/prefix (no system install)
# ends with: "gr-lora_sdr OK"
```

If the build can't find a header, install the matching `-dev` package and re-run; the script is
idempotent.

## 6. Configure

```bash
cp config.example.jsonc config.jsonc      # then add your channels / keys
./loraspy.py info                          # check frequencies, channel hashes, keys
./loraspy.py decoder enable all            # decoders start OFF; switch some (or all) on
```

## 7. Pass the RTL-SDR through to WSL (usbipd-win)

WSL doesn't see USB devices by default. Install **usbipd-win** on Windows and forward the dongle.

In **admin PowerShell** (one-time install):

```powershell
winget install usbipd
```

Each session (plug in the RTL-SDR first):

```powershell
usbipd list                       # find the RTL-SDR: "Realtek" / "RTL2838" / "Bulk-In, Bulk-Out"
usbipd bind   --busid <BUSID>     # one-time per device (admin); e.g. --busid 2-4
usbipd attach --wsl --busid <BUSID>
```

Back in **Ubuntu (WSL)** verify:

```bash
lsusb            # should list "Realtek Semiconductor Corp. RTL2838 ..."
rtl_test -t      # should detect the tuner (Ctrl-C to stop)
```

`usbipd detach --busid <BUSID>` returns it to Windows; re-`attach` after a replug or
`wsl --shutdown`.

## 8. Run

```bash
./loraspy.py listen                # decoded text
./loraspy.py listen --tui          # terminal UI
./loraspy.py listen --gui          # Qt window via WSLg (a real window on your Windows desktop)
```

One SDR is shared across front-ends exactly as on Linux (the Unix socket lives in
`$XDG_RUNTIME_DIR`, or `/tmp` without systemd).

---

## Troubleshooting

**`rtl_test` / osmosdr: "usb_claim_interface error -6" or "device busy".**
The kernel DVB driver grabbed the dongle. Blacklist it and replug:
```bash
echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/blacklist-rtl.conf
```
(then `usbipd detach`/`attach` again, or `wsl --shutdown`).

**Permission denied opening the RTL-SDR (no systemd).** Either enable systemd (step 3) so the
rtl-sdr udev rules apply, or run with `sudo` (note: `sudo` has a different `$XDG_RUNTIME_DIR`, so
start every front-end with `sudo` too, or pass a shared `--socket /tmp/loraspy.sock`).

**`lsusb` shows nothing after `usbipd attach`.** Your WSL kernel lacks usbip support — run
`wsl --update` (PowerShell), then `wsl --shutdown`, and attach again.

**`--gui` fails with a Qt "xcb"/platform-plugin error.** Make sure WSLg is current (`wsl --update`).
If it still fails, install the xcb helper libs: `sudo apt install -y libxcb-cursor0 libxkbcommon-x11-0`.
Confirm WSLg is present: `echo $WAYLAND_DISPLAY` and `echo $DISPLAY` should be non-empty.

**Overruns (`O` on the console) / spectrum shows but nothing decodes.** The spectrum FFT is already
decimated, but WSL2 + USB-over-IP adds latency; if the dongle can't keep real time, raise the RTL
ring buffering in `config.jsonc` (`"sdr": { "buffers": 32 }`), enable fewer decoders, or lower
`sample_rate`.

**gr-lora_sdr build fails.** Usually a missing `-dev` package — read the first CMake error, install
it, and re-run `./scripts/build_gr_lora_sdr.sh`. The common set is listed in step 4.

---

## Native Windows (without WSL)?

Running directly on Windows (e.g. with [radioconda](https://github.com/ryanvolz/radioconda) for
GNU Radio) would additionally need a Windows build of gr-lora_sdr and a port of the SDR-sharing
layer away from Unix domain sockets. That is not supported today; WSL2 is the recommended path.
