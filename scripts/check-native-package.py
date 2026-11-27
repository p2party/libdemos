#!/usr/bin/env python3
"""Verify an archive digest and consume both packaged libraries in an isolated directory."""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--checksums", type=Path, help="Published SHA256SUMS file")
    args = parser.parse_args()
    archive = args.archive.resolve()
    checksums = args.checksums or archive.with_name(archive.name + ".sha256")
    expected = f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}"
    if checksums.read_text().splitlines().count(expected) != 1:
        raise SystemExit("The archive does not match its expected SHA-256.")

    with tempfile.TemporaryDirectory() as scratch:
        consumer = Path(scratch).resolve()
        with tarfile.open(archive, "r:gz") as contents:
            contents.extractall(consumer, filter="data")
        package = consumer / archive.name.removesuffix(".tar.gz")
        source = consumer / "consumer.c"
        shutil.copyfile(Path(__file__).with_name("native-consumer.c"), source)
        system = platform.system()
        lib = package / "lib"
        shared = {"Darwin": "libdemos.dylib", "Linux": "libdemos.so", "Windows": "libdemos.dll.a"}[system]
        compiler = os.environ.get("CC", "gcc" if system == "Windows" else "cc")
        env = os.environ.copy()
        if system == "Windows":
            env["PATH"] = str(package / "bin") + os.pathsep + env["PATH"]
        for name in [shared, "libdemos_static.a"]:
            flags = ["-std=c11", "-Wall", "-Werror", "-I", str(package / "include")]
            if name == shared and system != "Windows":
                flags.append("-Wl,-rpath," + str(lib))
            if name != shared and system == "Windows":
                flags.append("-DDEMOS_PUBLIC=")
            executable = consumer / ("consumer.exe" if system == "Windows" else "consumer")
            subprocess.run([compiler, *flags, source, lib / name, "-lm", "-o", executable], cwd=consumer, check=True)
            subprocess.run([executable], cwd=consumer, env=env, check=True)
            print(f"Packaged consumer passed with {name}")


if __name__ == "__main__":
    main()
