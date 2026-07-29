"""SBOM output — CycloneDX 1.5 and SPDX 2.3.

Enterprise buyers and US federal contracts ask for one by name. Generating it from the
same lockfile parse the CVE scanner already did costs nothing extra.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from datetime import datetime, timezone

def _version() -> str:
    from .. import __version__
    return __version__


PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "Go": "golang",
             "crates.io": "cargo", "RubyGems": "gem"}


def purl(name: str, version: str, eco: str) -> str:
    t = PURL_TYPE.get(eco, eco.lower())
    if t == "npm" and name.startswith("@"):
        ns, _, pkg = name.partition("/")
        return f"pkg:npm/{urllib.parse.quote(ns, safe='')}/{pkg}@{version}"
    return f"pkg:{t}/{urllib.parse.quote(name, safe='')}@{version}"


def _serial(root: str) -> str:
    h = hashlib.sha256(root.encode()).hexdigest()
    return f"urn:uuid:{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def to_cyclonedx(packages, project_name: str, root: str,
                 project_license: str = "", timestamp: str | None = None) -> str:
    now = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    components = []
    for name, version, eco in packages:
        comp = {
            "type": "library",
            "bom-ref": purl(name, version, eco),
            "name": name,
            "version": version,
            "purl": purl(name, version, eco),
        }
        components.append(comp)

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": _serial(root),
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "Dhahab", "name": "dira", "version": _version()}],
            "component": {
                "type": "application",
                "bom-ref": f"root-{project_name}",
                "name": project_name,
                "version": "0.0.0",
                **({"licenses": [{"license": {"id": project_license}}]} if project_license else {}),
            },
        },
        "components": components,
    }
    return json.dumps(doc, indent=2)


def to_spdx(packages, project_name: str, root: str, timestamp: str | None = None) -> str:
    now = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pkgs = []
    rels = []
    for i, (name, version, eco) in enumerate(packages):
        spdx_id = f"SPDXRef-Package-{i}"
        pkgs.append({
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl(name, version, eco),
            }],
        })
        rels.append({"spdxElementId": "SPDXRef-DOCUMENT",
                     "relationshipType": "DESCRIBES" if i == 0 else "CONTAINS",
                     "relatedSpdxElement": spdx_id})

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-sbom",
        "documentNamespace": f"https://spdx.org/spdxdocs/{project_name}-{_serial(root)}",
        "creationInfo": {"created": now, "creators": [f"Tool: dira-{_version()}"]},
        "packages": pkgs,
        "relationships": rels,
    }
    return json.dumps(doc, indent=2)
