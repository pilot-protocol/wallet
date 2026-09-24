#!/usr/bin/env python3
"""Pack an io.pilot.wallet app-store bundle deterministically.

usage: pack-bundle.py <stage-dir> <out.tar.gz> <mtime-epoch>

Writes exactly two entries, manifest.json (0644) and bin/wallet (0755),
owned by 0:0 with a fixed mtime and a gzip header without name or time:
the layout pilotctl installs (the same entries as the wallet-v0.3.3
bundle, no directory entries). The same inputs give byte-identical output
on Linux and macOS, and macOS tar's AppleDouble/xattr entries never get in.
"""
import gzip, io, os, sys, tarfile

stage, out, mtime = sys.argv[1], sys.argv[2], int(sys.argv[3])
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
    for name, mode in (("manifest.json", 0o644), ("bin/wallet", 0o755)):
        path = os.path.join(stage, name)
        ti = tarfile.TarInfo(name)
        ti.size = os.path.getsize(path)
        ti.mode = mode
        ti.mtime = mtime
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        with open(path, "rb") as f:
            tf.addfile(ti, f)
with open(out, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
        gz.write(buf.getvalue())
