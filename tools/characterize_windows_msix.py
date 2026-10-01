#!/usr/bin/env python3
"""Produce a public-safe derived inventory from a Windows MSIX/AppX package."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone


def sha256_path(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_zip_entry(zf: zipfile.ZipFile, name: str) -> str:
    h = hashlib.sha256()
    with zf.open(name) as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def attrs(element: ET.Element) -> dict[str, str]:
    return {local_name(k): v for k, v in sorted(element.attrib.items())}


def walk_named(root: ET.Element, name: str) -> list[ET.Element]:
    return [e for e in root.iter() if local_name(e.tag) == name]


def classify_name(name: str) -> str:
    suffix = pathlib.PurePosixPath(name).suffix.lower()
    return suffix if suffix else "<none>"


def selected_file_markers(names: list[str]) -> dict[str, bool]:
    lower = [n.lower() for n in names]
    needles = {
        "chatgpt_executable": ("chatgpt.exe",),
        "codex_executable": ("codex.exe",),
        "chromium_or_electron": ("chrome_elf.dll", "resources.pak", "icudtl.dat", "electron"),
        "webview2": ("webview2",),
        "ffmpeg": ("ffmpeg",),
        "webrtc": ("webrtc",),
        "sqlite": ("sqlite", ".db", ".sqlite"),
        "node_runtime": ("node.exe", "node.dll"),
        "python_runtime": ("python.exe", "python3"),
        "mcp_strings": ("mcp",),
        "browser_assets": ("browser",),
        "voice_audio_assets": ("voice", "audio"),
        "computer_use": ("computer-use", "cua_node"),
        "windows_sandbox": ("windows-sandbox",),
        "chrome_extension_host": ("extension-host",),
        "tectonic": ("tectonic",),
    }
    return {
        key: any(any(needle in n for needle in values) for n in lower)
        for key, values in needles.items()
    }


def compact_paths(names: list[str], suffixes: set[str], limit: int = 200) -> list[str]:
    out = [n for n in names if pathlib.PurePosixPath(n).suffix.lower() in suffixes]
    return out[:limit]


def resource_topology(names: list[str]) -> dict:
    resources_prefix = "app/resources/"
    resource_roots = Counter()
    unpacked_modules = set()
    bundled_plugins = set()

    for name in names:
        normalized = name.replace("\\", "/")
        if normalized.startswith(resources_prefix):
            rest = normalized[len(resources_prefix):]
            first = rest.split("/", 1)[0]
            if first:
                resource_roots[first] += 1

        marker = "app/resources/app.asar.unpacked/node_modules/"
        if normalized.startswith(marker):
            rest = normalized[len(marker):]
            parts = rest.split("/")
            if parts:
                if parts[0].startswith("@") and len(parts) > 1:
                    unpacked_modules.add(parts[0] + "/" + parts[1])
                else:
                    unpacked_modules.add(parts[0])

        plugin_marker = "app/resources/plugins/openai-bundled/plugins/"
        if normalized.startswith(plugin_marker):
            rest = normalized[len(plugin_marker):]
            plugin = rest.split("/", 1)[0]
            if plugin:
                bundled_plugins.add(plugin)

    return {
        "resource_roots": dict(sorted(resource_roots.items())),
        "asar_unpacked_node_modules": sorted(unpacked_modules),
        "bundled_plugin_ids": sorted(bundled_plugins),
    }


def characterize(path: pathlib.Path, source_url: str, architecture_hint: str) -> dict:
    if not zipfile.is_zipfile(path):
        raise SystemExit(f"{path} is not a ZIP-compatible MSIX/AppX package")

    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        info_by_name = {i.filename: i for i in infos if not i.is_dir()}
        names = list(info_by_name)
        manifest_name = next(
            (n for n in names if n.lower() == "appxmanifest.xml"),
            None,
        )
        if manifest_name is None:
            raise SystemExit("AppxManifest.xml missing")

        manifest_bytes = zf.read(manifest_name)
        root = ET.fromstring(manifest_bytes)

        identity = attrs(walk_named(root, "Identity")[0]) if walk_named(root, "Identity") else {}
        properties = {
            local_name(c.tag): (c.text or "").strip()
            for p in walk_named(root, "Properties")[:1]
            for c in list(p)
        }

        dependencies = []
        for dep in walk_named(root, "PackageDependency"):
            dependencies.append({"kind": "PackageDependency", **attrs(dep)})
        for dep in walk_named(root, "TargetDeviceFamily"):
            dependencies.append({"kind": "TargetDeviceFamily", **attrs(dep)})

        capabilities = []
        for element in root.iter():
            if local_name(element.tag).endswith("Capability"):
                entry = attrs(element)
                if entry:
                    entry["element"] = local_name(element.tag)
                    capabilities.append(entry)

        applications = []
        for app in walk_named(root, "Application"):
            item = attrs(app)
            item["visual_elements"] = [
                attrs(e)
                for e in app.iter()
                if local_name(e.tag) in {"VisualElements", "DefaultTile", "SplashScreen"}
            ]
            item["extensions"] = [
                {"element": local_name(e.tag), **attrs(e)}
                for e in app.iter()
                if local_name(e.tag) in {"Extension", "Protocol", "FileTypeAssociation"}
            ]
            applications.append(item)

        extensions = [
            {"element": local_name(e.tag), **attrs(e)}
            for e in root.iter()
            if local_name(e.tag) in {
                "Extension",
                "Protocol",
                "FileTypeAssociation",
                "AppExecutionAlias",
            }
        ]

        file_types = Counter(classify_name(n) for n in names)
        total_uncompressed = sum(i.file_size for i in infos if not i.is_dir())
        total_compressed = sum(i.compress_size for i in infos if not i.is_dir())

        executable_paths = compact_paths(names, {".exe"}, 300)
        dll_paths = compact_paths(names, {".dll"}, 500)
        native_paths = compact_paths(names, {".node", ".wasm", ".pyd"}, 300)
        config_paths = compact_paths(
            names,
            {".json", ".toml", ".yaml", ".yml", ".xml", ".config"},
            300,
        )

        asar_paths = [n for n in names if n.lower().endswith(".asar")]
        asar_archives = [
            {
                "path": name,
                "size_bytes": info_by_name[name].file_size,
                "compressed_bytes": info_by_name[name].compress_size,
                "sha256": sha256_zip_entry(zf, name),
            }
            for name in asar_paths
        ]

        p7x_name = next((n for n in names if n.lower() == "appxsignature.p7x"), None)
        signature = {
            "present": p7x_name is not None,
            "entry": p7x_name,
            "sha256": sha256_zip_entry(zf, p7x_name) if p7x_name else None,
            "verification": "not-performed-by-linux-static-rep",
        }

        return {
            "schema": "cdr-derived-windows-msix-surface/v2",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": {
                "url": source_url,
                "source_class": "official-openai-store-signed-stable-link",
                "architecture_hint": architecture_hint,
            },
            "package": {
                "filename": path.name,
                "sha256": sha256_path(path),
                "size_bytes": path.stat().st_size,
                "zip_entry_count": len(names),
                "uncompressed_bytes": total_uncompressed,
                "compressed_bytes": total_compressed,
                "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "identity": identity,
                "properties": properties,
                "signature": signature,
            },
            "manifest": {
                "dependencies": dependencies,
                "capabilities": capabilities,
                "applications": applications,
                "extensions": extensions,
            },
            "runtime_topology": {
                "asar_archives": asar_archives,
                **resource_topology(names),
            },
            "files": {
                "extension_counts": dict(sorted(file_types.items())),
                "executable_count": len(executable_paths),
                "dll_count": len(dll_paths),
                "native_auxiliary_count": len(native_paths),
                "executables": executable_paths,
                "libraries_sample": dll_paths,
                "native_auxiliary_sample": native_paths,
                "configuration_sample": config_paths,
                "selected_markers": selected_file_markers(names),
            },
            "claim_boundary": (
                "Static package-derived evidence only. Presence identifies packaged surface; "
                "absence does not prove runtime capability absence. ASAR contents are hashed/topologized "
                "without publishing extracted proprietary source. No proprietary package bytes are included."
            ),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=pathlib.Path)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    result = characterize(args.package, args.source_url, args.architecture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    p = result["package"]
    print(json.dumps({
        "schema": result["schema"],
        "identity": p["identity"],
        "sha256": p["sha256"],
        "size_bytes": p["size_bytes"],
        "zip_entry_count": p["zip_entry_count"],
        "signature": p["signature"],
        "capability_count": len(result["manifest"]["capabilities"]),
        "extension_count": len(result["manifest"]["extensions"]),
        "executable_count": result["files"]["executable_count"],
        "dll_count": result["files"]["dll_count"],
        "asar_archives": result["runtime_topology"]["asar_archives"],
        "asar_unpacked_node_modules": result["runtime_topology"]["asar_unpacked_node_modules"],
        "bundled_plugin_ids": result["runtime_topology"]["bundled_plugin_ids"],
        "selected_markers": result["files"]["selected_markers"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
