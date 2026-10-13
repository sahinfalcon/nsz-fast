#!/usr/bin/env python3
"""Run upstream nsz and nsz-fast on the same game file, check the outputs are
byte-identical (SHA-256) and compare how long each takes.

Usage:
    python scripts/compare_upstream.py --keys ~/.switch/prod.keys game.nsp
    python scripts/compare_upstream.py --keys KEYS --upstream ~/src/nsz --modes solid,verify game.nsp

Modes: solid (-C -V), block (-B -C -V), verify (-V on the solid output),
decompress (-D on the solid output; must reproduce the original file).
Each output is hashed and deleted right away, so --work needs room for about
twice the game's size.
"""
import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FORK_DIR = Path(__file__).resolve().parent.parent
UPSTREAM_URL = "https://github.com/nicoboss/nsz"
COMPRESSED_SUFFIX = {".nsp": ".nsz", ".xci": ".xcz"}
ALL_MODES = ("solid", "verify", "decompress", "block")


def sha256File(path, chunkSize=16 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunkSize), b""):
            h.update(chunk)
    return h.hexdigest()


def onlyFile(directory, suffix):
    found = sorted(directory.glob("*" + suffix))
    return found[0] if len(found) == 1 else None


class Comparison:
    def __init__(self, game, keys, upstreamDir, work, keep):
        self.game = game
        self.keys = keys
        self.impls = (("upstream", upstreamDir), ("nsz-fast", FORK_DIR))
        self.work = work
        self.keep = keep
        self.rows = []
        self.solidOutput = None
        self.gameHash = None

    def runNsz(self, nszDir, args, label):
        start = time.perf_counter()
        with open(str(self.work / (label + ".log")), "w") as log:
            code = subprocess.run(
                [sys.executable, str(nszDir / "nsz.py"), "--keys", str(self.keys)] + args,
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=str(self.work),
            ).returncode
        return time.perf_counter() - start, code

    def runBoth(self, mode, argsFor, outputSuffix=None, keepUpstreamOutput=False):
        """Returns ({impl: seconds}, {impl: sha256 of the output or None}, error note)."""
        times, hashes, failed = {}, {}, []
        for name, nszDir in self.impls:
            outDir = self.work / "{0}-{1}".format(mode, name)
            outDir.mkdir()
            elapsed, code = self.runNsz(nszDir, argsFor(outDir), "{0}-{1}".format(mode, name))
            times[name] = elapsed
            output = onlyFile(outDir, outputSuffix) if outputSuffix else None
            if code != 0 or (outputSuffix and output is None):
                failed.append(name)
            hashes[name] = sha256File(output) if output else None
            print("  {0:<10} {1:<9} {2:7.1f}s  exit {3}".format(mode, name, elapsed, code), flush=True)
            if keepUpstreamOutput and name == "upstream" and output:
                self.solidOutput = output
            elif not self.keep:
                shutil.rmtree(str(outDir), ignore_errors=True)
        note = "{0} failed, see {1}".format(" and ".join(failed), self.work) if failed else ""
        return times, hashes, note

    def compress(self, mode, flags, keepUpstreamOutput=False):
        times, hashes, note = self.runBoth(
            mode,
            lambda out: flags + ["-o", str(out), str(self.game)],
            COMPRESSED_SUFFIX[self.game.suffix],
            keepUpstreamOutput,
        )
        identical = not note and hashes["upstream"] == hashes["nsz-fast"]
        self.rows.append((mode, times, identical, note))

    def solid(self):
        self.compress("solid", ["-C", "-V"], keepUpstreamOutput=True)

    def block(self):
        self.compress("block", ["-B", "-C", "-V"])

    def needSolidOutput(self, mode):
        if self.solidOutput is None:
            print("  (compressing with upstream first to get a file to {0})".format(mode), flush=True)
            outDir = self.work / "solid-upstream"
            outDir.mkdir(exist_ok=True)
            self.runNsz(self.impls[0][1], ["-C", "-o", str(outDir), str(self.game)], "prep")
            self.solidOutput = onlyFile(outDir, COMPRESSED_SUFFIX[self.game.suffix])
        if self.solidOutput is None:
            self.rows.append((mode, None, False, "upstream compression failed, see prep.log"))
        return self.solidOutput

    def verify(self):
        compressed = self.needSolidOutput("verify")
        if compressed:
            times, _, note = self.runBoth("verify", lambda out: ["-V", str(compressed)])
            self.rows.append(("verify", times, None, note))

    def decompress(self):
        compressed = self.needSolidOutput("decompress")
        if not compressed:
            return
        times, hashes, note = self.runBoth(
            "decompress", lambda out: ["-D", "-o", str(out), str(compressed)], self.game.suffix
        )
        if self.gameHash is None:
            self.gameHash = sha256File(self.game)
        identical = not note and hashes["upstream"] == hashes["nsz-fast"]
        if identical and hashes["nsz-fast"] != self.gameHash:
            note = "both differ from the original file"
        self.rows.append(("decompress", times, identical, note))

    def report(self):
        print("\n{0:<11} {1:>10} {2:>10} {3:>8}  {4}".format("mode", "upstream", "nsz-fast", "speedup", "output"))
        ok = True
        for mode, times, identical, note in self.rows:
            ok = ok and not note and identical is not False
            verdict = "n/a" if identical is None else ("identical" if identical else "DIFFERENT")
            if times:
                up, fast = times["upstream"], times["nsz-fast"]
                print("{0:<11} {1:>9.1f}s {2:>9.1f}s {3:>7.2f}x  {4} {5}".format(mode, up, fast, up / fast, verdict, note))
            else:
                print("{0:<11} {1:>10} {1:>10} {1:>8}  {2} {3}".format(mode, "-", verdict, note))
        return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("game", type=Path, help=".nsp or .xci file")
    parser.add_argument("--keys", type=Path, required=True, help="prod.keys file or the folder containing it")
    parser.add_argument("--upstream", type=Path, help="upstream nsz checkout (cloned from GitHub if omitted)")
    parser.add_argument("--modes", default=",".join(ALL_MODES), help="comma-separated subset of " + ",".join(ALL_MODES))
    parser.add_argument("--work", type=Path, help="scratch directory for outputs (default: a temp dir)")
    parser.add_argument("--keep", action="store_true", help="keep the output files")
    args = parser.parse_args()

    game = args.game.expanduser().resolve()
    if game.suffix not in COMPRESSED_SUFFIX:
        parser.error("game must be a .nsp or .xci file")
    modes = [m for m in args.modes.split(",") if m]
    unknown = set(modes) - set(ALL_MODES)
    if unknown:
        parser.error("unknown modes: " + ", ".join(sorted(unknown)))

    work = Path(tempfile.mkdtemp(prefix="nsz-compare-", dir=str(args.work) if args.work else None))
    if args.upstream:
        upstreamDir = args.upstream.expanduser().resolve()
    else:
        upstreamDir = work / "upstream-nsz"
        subprocess.run(["git", "clone", "-q", "--depth", "1", UPSTREAM_URL, str(upstreamDir)], check=True)

    comparison = Comparison(game, args.keys.expanduser().resolve(), upstreamDir, work, args.keep)
    print("Comparing on {0} ({1:.2f} GB), work dir {2}".format(game.name, game.stat().st_size / 1e9, work), flush=True)
    for mode in ALL_MODES:
        if mode in modes:
            getattr(comparison, mode)()
        if mode == "decompress" and comparison.solidOutput and not args.keep:
            # Free the space before block mode writes its outputs
            shutil.rmtree(str(comparison.solidOutput.parent), ignore_errors=True)
            comparison.solidOutput = None
    ok = comparison.report()
    print("\nLogs: " + str(work))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
