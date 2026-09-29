"""
Import gr-lora_sdr, either system-installed or from the local build in deps/prefix
(scripts/build_gr_lora_sdr.sh). The local build is a second `gnuradio/` package
directory, so it is grafted onto the system gnuradio package's __path__.
"""

import ctypes
import glob
import os
import sys
from pathlib import Path

DEFAULT_PREFIX = Path(__file__).resolve().parent.parent / "deps" / "prefix"


def import_lora_sdr():
    import gnuradio

    try:
        from gnuradio import lora_sdr
        return lora_sdr
    except ImportError:
        pass

    prefix = Path(os.environ.get("MESHSDR_GR_PREFIX", DEFAULT_PREFIX))
    pkg_dirs = glob.glob(str(prefix / "lib*" / f"python3.{sys.version_info.minor}" / "site-packages" / "gnuradio"))
    libs = glob.glob(str(prefix / "lib*" / "libgnuradio-lora_sdr.so"))
    if not pkg_dirs or not libs:
        raise ImportError(
            "gr-lora_sdr not found. Install it system-wide (AUR: gr-lora_sdr-git) or run "
            "scripts/build_gr_lora_sdr.sh to build it into deps/prefix "
            f"(looked in {prefix}, override with MESHSDR_GR_PREFIX).")
    # Load the C++ library globally so the pybind module resolves it without LD_LIBRARY_PATH
    ctypes.CDLL(libs[0], mode=ctypes.RTLD_GLOBAL)
    gnuradio.__path__.append(pkg_dirs[0])
    from gnuradio import lora_sdr
    return lora_sdr
