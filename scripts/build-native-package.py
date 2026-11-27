#!/usr/bin/env python3
"""Build, test and archive the native voting library from a clean checkout."""

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SODIUM = ROOT / "libsodium"
INCLUDE_PREFIX = "../libsodium/src/libsodium/include/sodium/"


def output(*args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def install_headers(destination):
    public_header = (ROOT / "include/demos.h").read_text()
    (destination / "sodium").mkdir(parents=True)
    (destination / "demos.h").write_text(public_header.replace(INCLUDE_PREFIX, "sodium/"))

    # The source header references the submodule checkout. Ship only the
    # headers its declarations include, including their quoted dependencies.
    pending = re.findall(r'^#include "' + re.escape(INCLUDE_PREFIX) + r'([^"]+)"', public_header, re.M)
    installed = set()
    while pending:
        name = pending.pop()
        if name in installed:
            continue
        installed.add(name)
        source = SODIUM / "src/libsodium/include/sodium" / name
        shutil.copyfile(source, destination / "sodium" / name)
        pending.extend(re.findall(r'^\s*#\s*include\s*"([^"]+)"', source.read_text(), re.M))


def archive(directory, filename, epoch):
    with filename.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as stream:
        with tarfile.open(fileobj=stream, mode="w") as package:
            for source in sorted(directory.rglob("*")):
                if not source.is_file():
                    continue
                name = (Path(directory.name) / source.relative_to(directory)).as_posix()
                info = tarfile.TarInfo(name)
                info.size = source.stat().st_size
                info.mode = 0o755 if source.suffix in {".dylib", ".dll", ".so"} else 0o644
                info.mtime = epoch
                with source.open("rb") as contents:
                    package.addfile(info, contents)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)

    version = re.search(r"project\(demos VERSION ([\d.]+)\)", (ROOT / "CMakeLists.txt").read_text())[1]
    revision = output("git", "rev-parse", "HEAD")
    sodium_revision = output("git", "rev-parse", "HEAD", cwd=SODIUM)
    if output("git", "rev-parse", "HEAD:libsodium") != sodium_revision:
        raise SystemExit("Initialize the exact libsodium submodule recorded by this revision.")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, check=True)
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=SODIUM, check=True)
    epoch = int(output("git", "show", "-s", "--format=%ct", "HEAD"))

    system = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}[platform.system()]
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}[platform.machine().lower()]
    name = f"libdemos-{version}-{system}-{arch}"
    compiler = os.environ.get("CC", "gcc" if system == "windows" else "cc")

    with tempfile.TemporaryDirectory() as scratch:
        temporary = Path(scratch).resolve()
        build = temporary / "build"
        stage = temporary / name
        (stage / "lib").mkdir(parents=True)
        source_paths = {ROOT.as_posix(): ".", temporary.as_posix(): "build"}
        compile_flags = [f'"-ffile-prefix-map={source}={alias}"' for source, alias in source_paths.items()]
        if system == "windows":
            # Tests link to the static library. Its declarations must not use dllimport.
            compile_flags.append("-DDEMOS_PUBLIC=")
        subprocess.run([
            "cmake", "-G", "Ninja", "-S", ROOT, "-B", build, "-DCMAKE_BUILD_TYPE=Release",
            f"-DCMAKE_C_COMPILER={compiler}", "-DCMAKE_C_FLAGS=" + " ".join(compile_flags),
        ], check=True)
        suites = ("commit", "shamir", "crypto", "merkle")
        subprocess.run([
            "cmake", "--build", build, "--parallel", "4", "--target", "demos", "demos_static",
            *(suite + "_test" for suite in suites),
        ], check=True)
        for suite in suites:
            executable = suite + "_test" + (".exe" if system == "windows" else "")
            subprocess.run([build / "__tests__" / executable], cwd=temporary, check=True)

        libraries = ["libdemos_static.a"]
        if system == "windows":
            (stage / "bin").mkdir()
            shutil.copyfile(build / "libdemos.dll", stage / "bin/libdemos.dll")
            libraries.append("libdemos.dll.a")
        else:
            libraries.append("libdemos.dylib" if system == "macos" else "libdemos.so")
        for library in libraries:
            shutil.copyfile(build / library, stage / "lib" / library)
        install_headers(stage / "include")
        shutil.copyfile(ROOT / "LICENSE", stage / "LICENSE")
        shutil.copyfile(SODIUM / "LICENSE", stage / "libsodium.LICENSE")
        (stage / "BUILDINFO.txt").write_text(
            f"libdemos {version}\nsource {revision}\nlibsodium {sodium_revision}\ntarget {system}-{arch}\n"
            + f"compiler {output(compiler, '--version').splitlines()[0]}\n", newline="\n"
        )
        # Compiler diagnostics and binary debug records must not disclose build paths.
        private_paths = {str(path).encode() for path in [ROOT, temporary]} | {p.encode() for p in source_paths}
        for path in stage.rglob("*"):
            if path.is_file():
                contents = path.read_bytes()
                if any(prefix in contents for prefix in private_paths):
                    raise SystemExit(f"A build path was embedded in {path.name}.")
        package = destination / (name + ".tar.gz")
        archive(stage, package, epoch)
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    (destination / (package.name + ".sha256")).write_text(f"{digest}  {package.name}\n", newline="\n")
    print(f"{digest}  {package.name}")


if __name__ == "__main__":
    main()
