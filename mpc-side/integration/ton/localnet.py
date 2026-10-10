"""Pinned isolated validator fixture; keep its private volume out of artifacts."""

import hashlib
import subprocess

from custody.ton_proofs import Cell, TonProofClient

IMAGE = (
    "ghcr.io/ton-blockchain/localton@sha256:"
    "c5dd9dcb3f662c85ec0636c19b85664b69ccad554ef69b6adf3864e7e9e82387"
)


def docker(*args):
    return subprocess.check_output(["docker", *map(str, args)], stderr=subprocess.STDOUT, text=True)


def capture(container, root):
    if docker("inspect", "--format", "{{.Config.Image}}", container).strip() != IMAGE:
        raise ValueError("unreviewed Localton container image")
    root.mkdir(parents=True, exist_ok=True)
    for source, dest in (
        ("/opt/ton/lite-client", "lite-client"),
        ("/var/lib/localton/global.config.json", "global.config.json"),
        ("/var/lib/localton/settings.json", "localton-settings.json"),
        ("/var/lib/localton/genesis/zerostate/zerostate.boc", "zerostate.boc"),
        ("/var/lib/localton/genesis/zerostate/basestate0.boc", "basestate0.boc"),
    ):
        docker("cp", container + ":" + source, root / dest)
    identity = {
        "network": "isolated-acton-v1",
        "genesis_source": "localton-generated-zerostate",
        "global_id": -777,
        "settings_sha256": hashlib.sha256(
            (root / "localton-settings.json").read_bytes()
        ).hexdigest(),
        "image_digest": IMAGE.split("sha256:")[1],
    }
    for name, p in (("zerostate", "zerostate.boc"), ("basechain_zerostate", "basestate0.boc")):
        raw = (root / p).read_bytes()
        identity[name + "_root_hash"] = Cell.one_from_boc(raw).hash.hex()
        identity[name + "_file_hash"] = hashlib.sha256(raw).hexdigest()
    return TonProofClient(
        binary=root / "lite-client",
        config=root / "global.config.json",
        zerostate=root / "zerostate.boc",
        basestate=root / "basestate0.boc",
        settings_file=root / "localton-settings.json",
        identity=identity,
    )


def fund(container, address, amount):
    return docker(
        "exec",
        container,
        "localton",
        "wallet",
        "fund",
        "--state-dir",
        "/var/lib/localton",
        address,
        str(amount),
    )


def provision(root, container):
    """Fresh CI genesis only; callers explicitly opt in, never replace a volume."""
    import json
    import time

    docker("pull", IMAGE)
    volume = container + "-state"
    # Refuse destructive recreation; the resumed workspace uses capture directly.
    if container in docker("ps", "-a", "--format", "{{.Names}}").splitlines():
        raise ValueError("preserve existing Localnet container")
    if volume in docker("volume", "ls", "--format", "{{.Name}}").splitlines():
        raise ValueError("preserve existing Localnet genesis volume")
    docker("volume", "create", volume)
    init = container + "-init"
    docker(
        "run",
        "--name",
        init,
        "-v",
        volume + ":/var/lib/localton",
        IMAGE,
        "config",
        "init",
        "--state-dir",
        "/var/lib/localton",
    )
    root.mkdir(parents=True, exist_ok=True)
    settings = root / "genesis-settings.json"
    docker("cp", init + ":/var/lib/localton/settings.json", settings)
    config = json.loads(settings.read_text())
    config["network"]["global_id"] = -777
    settings.write_text(json.dumps(config, indent=2) + "\n")
    docker("cp", settings, init + ":/var/lib/localton/settings.json")
    docker("rm", init)
    docker(
        "run",
        "-d",
        "--name",
        container,
        "-p",
        "127.0.0.1:18004:18004",
        "-p",
        "127.0.0.1:18002:18002",
        "-v",
        volume + ":/var/lib/localton",
        IMAGE,
        "bootstrap",
        "--state-dir",
        "/var/lib/localton",
        "--ton-http-api",
        "--ton-http-api-bind",
        "0.0.0.0",
        "--startup-timeout",
        "180",
        "--no-admin-http",
        "--no-observability",
    )
    for _ in range(180):
        try:
            result = json.loads(
                docker(
                    "exec",
                    container,
                    "localton",
                    "lite",
                    "last",
                    "--state-dir",
                    "/var/lib/localton",
                )
            )
            if result["seqno"] >= 3:
                return
        except (subprocess.CalledProcessError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError("isolated validator did not establish genesis blocks")


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    p.add_argument("--container", required=True)
    a = p.parse_args()
    provision(a.root, a.container)
