#!/usr/bin/env python3
import os
import sys
import inspect
import click
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET
from glob import glob

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

root = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    )
)
desktop_dir = os.path.join(root, "desktop")


def get_size(dir):
    size = 0
    for path, dirs, files in os.walk(dir):
        for f in files:
            fp = os.path.join(path, f)
            size += os.path.getsize(fp)
    return size


def run(cmd, cwd=None, error_ok=False):
    print(cmd)
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
    except subprocess.CalledProcessError as e:
        if not error_ok:
            raise subprocess.CalledProcessError(e)


def sign(filename):
    click.echo(f"> Signing {filename}")
    run(
        [
            shutil.which("signtool.exe"),
            "sign",
            "/v",
            "/d",
            "OnionShare",
            "/n",
            "Lockdown Systems LLC",
            "/fd",
            "sha256",
            "/td",
            "sha256",
            "/tr",
            "http://ts.harica.gr",
            filename,
        ]
    )


def wix_build_data(dirname, dir_prefix, id_, name, skip_basenames=None):
    skip_basenames = set(skip_basenames or ())
    data = {
        "id": id_,
        "name": name,
        "files": [],
        "dirs": [],
    }

    for basename in os.listdir(dirname):
        filename = os.path.join(dirname, basename)
        if os.path.isfile(filename):
            if basename in skip_basenames:
                continue
            data["files"].append(os.path.join(dir_prefix, basename))
        elif os.path.isdir(filename):
            if id_ == "INSTALLDIR":
                id_prefix = "Folder"
            else:
                id_prefix = id_

            # Skip lib/Pyside2/Examples folder
            if "\\lib\\PySide2\\examples" in dirname:
                continue

            id_value = f"{id_prefix}{basename.capitalize().replace('-', '_')}"
            data["dirs"].append(
                wix_build_data(
                    os.path.join(dirname, basename),
                    os.path.join(dir_prefix, basename),
                    id_value,
                    basename,
                    skip_basenames,
                )
            )

    if len(data["files"]) > 0:
        if id_ == "INSTALLDIR":
            data["component_id"] = "ApplicationFiles"
        else:
            data["component_id"] = "FolderComponent" + id_[len("Folder") :]
        data["component_guid"] = str(uuid.uuid4())

    return data


def wix_build_dir_xml(
    root,
    data,
    *,
    shortcut_name="OnionShare",
    shortcut_description="OnionShare",
    registry_key="Software\\OnionShare",
    shortcut_component_guid="539e7de8-a124-4c09-aa55-0dd516aad7bc",
):
    attrs = {}
    if "id" in data:
        attrs["Id"] = data["id"]
    if "name" in data:
        attrs["Name"] = data["name"]
    el = ET.SubElement(root, "Directory", attrs)
    for subdata in data["dirs"]:
        wix_build_dir_xml(
            el,
            subdata,
            shortcut_name=shortcut_name,
            shortcut_description=shortcut_description,
            registry_key=registry_key,
            shortcut_component_guid=shortcut_component_guid,
        )

    # If this is the ProgramMenuFolder, add the menu component
    if "id" in data and data["id"] == "ProgramMenuFolder":
        component_el = ET.SubElement(
            el,
            "Component",
            Id="ApplicationShortcuts",
            Guid=shortcut_component_guid,
            Win64="yes",
        )
        ET.SubElement(
            component_el,
            "Shortcut",
            Id="ApplicationShortcut1",
            Name=shortcut_name,
            Description=shortcut_description,
            Target="[INSTALLDIR]onionshare.exe",
            WorkingDirectory="INSTALLDIR",
        )
        ET.SubElement(
            component_el,
            "RegistryValue",
            Root="HKCU",
            Key=registry_key,
            Name="installed",
            Type="integer",
            Value="1",
            KeyPath="yes",
        )


def wix_build_components_xml(root, data):
    component_ids = []
    if "component_id" in data:
        component_ids.append(data["component_id"])

    for subdata in data["dirs"]:
        if "component_guid" in subdata:
            dir_ref_el = ET.SubElement(root, "DirectoryRef", Id=subdata["id"])
            component_el = ET.SubElement(
                dir_ref_el,
                "Component",
                Id=subdata["component_id"],
                Guid=subdata["component_guid"],
                Win64="yes",
            )
            for filename in subdata["files"]:
                file_el = ET.SubElement(
                    component_el, "File", Source=filename, Id="file_" + uuid.uuid4().hex
                )

        component_ids += wix_build_components_xml(root, subdata)

    return component_ids


def msi_package(
    build_path,
    msi_path,
    product_update_code,
    version,
    *,
    product_name="OnionShare",
    install_dir_name="OnionShare",
    shortcut_name="OnionShare",
    shortcut_description="OnionShare",
    registry_key="Software\\OnionShare",
    shortcut_component_guid="539e7de8-a124-4c09-aa55-0dd516aad7bc",
    manufacturer="Micah Lee, et al.",
    installer_description=None,
    skip_basenames=None,
    sign_package=True,
):
    print("> Build the WiX file")

    # change a version like 2.6.dev1 to just 2.6, for cx_Freeze's sake
    last_digit = version[-1]
    if version.endswith(f".dev{last_digit}"):
        version = version[0:-5]

    data = {
        "id": "TARGETDIR",
        "name": "SourceDir",
        "dirs": [
            {
                "id": "ProgramFiles64Folder",
                "dirs": [],
            },
            {
                "id": "ProgramMenuFolder",
                "dirs": [],
            },
        ],
    }

    data["dirs"][0]["dirs"].append(
        wix_build_data(
            build_path,
            ".",
            "INSTALLDIR",
            install_dir_name,
            skip_basenames,
        )
    )

    if installer_description is None:
        installer_description = f"{product_name} $(var.ProductVersion) Installer"

    root_el = ET.Element("Wix", xmlns="http://schemas.microsoft.com/wix/2006/wi")
    product_el = ET.SubElement(
        root_el,
        "Product",
        Name=product_name,
        Manufacturer=manufacturer,
        Id="*",
        UpgradeCode="$(var.ProductUpgradeCode)",
        Language="1033",
        Codepage="1252",
        Version="$(var.ProductVersion)",
    )
    ET.SubElement(
        product_el,
        "Package",
        Id="*",
        Keywords="Installer",
        Description=installer_description,
        Manufacturer=manufacturer,
        InstallerVersion="200",
        Languages="1033",
        Compressed="yes",
        SummaryCodepage="1252",
        Platform="x64",
    )
    ET.SubElement(product_el, "Media", Id="1", Cabinet="product.cab", EmbedCab="yes")
    ET.SubElement(
        product_el,
        "Icon",
        Id="ProductIcon",
        SourceFile=os.path.join(
            desktop_dir, "onionshare", "resources", "onionshare.ico"
        ),
    )
    ET.SubElement(product_el, "Property", Id="ARPPRODUCTICON", Value="ProductIcon")
    ET.SubElement(
        product_el,
        "Property",
        Id="ARPHELPLINK",
        Value="https://docs.onionshare.org",
    )
    ET.SubElement(
        product_el,
        "Property",
        Id="ARPURLINFOABOUT",
        Value="https://onionshare.org",
    )
    ET.SubElement(product_el, "UIRef", Id="WixUI_Minimal")
    ET.SubElement(product_el, "UIRef", Id="WixUI_ErrorProgressText")
    ET.SubElement(
        product_el,
        "WixVariable",
        Id="WixUILicenseRtf",
        Value=os.path.join(desktop_dir, "package", "license.rtf"),
    )
    ET.SubElement(
        product_el,
        "WixVariable",
        Id="WixUIDialogBmp",
        Value=os.path.join(desktop_dir, "package", "dialog.bmp"),
    )
    ET.SubElement(
        product_el,
        "MajorUpgrade",
        AllowSameVersionUpgrades="yes",
        DowngradeErrorMessage="A newer version of [ProductName] is already installed. If you are sure you want to downgrade, remove the existing installation via Programs and Features.",
    )

    wix_build_dir_xml(
        product_el,
        data,
        shortcut_name=shortcut_name,
        shortcut_description=shortcut_description,
        registry_key=registry_key,
        shortcut_component_guid=shortcut_component_guid,
    )
    component_ids = wix_build_components_xml(product_el, data)

    feature_el = ET.SubElement(product_el, "Feature", Id="DefaultFeature", Level="1")
    for component_id in component_ids:
        ET.SubElement(feature_el, "ComponentRef", Id=component_id)
    ET.SubElement(feature_el, "ComponentRef", Id="ApplicationShortcuts")

    with open(os.path.join(build_path, "OnionShare.wxs"), "w") as f:
        f.write('<?xml version="1.0" encoding="windows-1252"?>\n')
        f.write(f'<?define ProductVersion = "{version}"?>\n')
        f.write(f'<?define ProductUpgradeCode = "{product_update_code}"?>\n')

        ET.indent(root_el)
        f.write(ET.tostring(root_el).decode())

    print(f"> Build the MSI")
    run(
        [shutil.which("candle.exe"), "OnionShare.wxs"],
        build_path,
    )
    run(
        [shutil.which("light.exe"), "-ext", "WixUIExtension", "OnionShare.wixobj"],
        build_path,
    )

    if sign_package:
        print("> Prepare OnionShare.msi for signing")
        run(
            [
                shutil.which("insignia.exe"),
                "-im",
                os.path.join(build_path, "OnionShare.msi"),
            ],
            error_ok=True,
        )
        sign(os.path.join(build_path, "OnionShare.msi"))
    else:
        print("> Skipping insignia and signtool for the unsigned fork MSI")

    print(f"> Final MSI: {msi_path}")
    os.makedirs(os.path.join(desktop_dir, "dist"), exist_ok=True)
    os.rename(
        os.path.join(build_path, "OnionShare.msi"),
        msi_path,
    )


@click.group()
def main():
    """
    Windows build tasks
    """


@main.command()
def cleanup_build():
    """Delete unused PySide6 stuff to save space"""
    build_path = os.path.join(desktop_dir, "build", "exe.win-amd64-3.12")
    before_size = get_size(build_path)

    for dirname in ["qml"]:
        shutil.rmtree(os.path.join(build_path, "lib", "PySide6", dirname))
    for dirname in [
        "assetimporters",
        "designer",
        "generic",
        "geometryloaders",
        "platforminputcontexts",
        "position",
        "qmltooling",
        "renderers",
        "renderplugins",
        "sceneparsers",
        "scxmldatamodel",
        "sensors",
        "sqldrivers",
        "styles",
    ]:
        shutil.rmtree(os.path.join(build_path, "lib", "PySide6", "plugins", dirname))
    for filename in (
        glob(os.path.join(build_path, "lib", "PySide6", "*.exe"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt3D*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt63D*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Bluetooth.*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Charts*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Concurrent.*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6DataVisualization*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Bus.dll"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Designer*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Help.dll"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Labs*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Multimedia*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Nfc.dll"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6OpenGL*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Qml*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Quick*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6RemoteObjects*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Scxml*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Sensors*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6SerialPort.*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6ShaderTools.*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Sql.*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6StateMachine*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Test.*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6VirtualKeyboard.*"))
        + glob(os.path.join(build_path, "lib", "PySide6", "Qt6Web*"))
    ):
        os.remove(filename)

    after_size = get_size(build_path)
    freed_bytes = before_size - after_size
    freed_mb = int(freed_bytes / 1024 / 1024)
    print(f"Freed {freed_mb} mb")


@main.command()
@click.argument("path")
def codesign(path):
    """Sign Windows binaries before packaging"""
    if not os.path.isdir(path):
        click.echo("Invalid build path")
        return

    sign(os.path.join(path, "onionshare.exe"))
    sign(os.path.join(path, "onionshare-cli.exe"))
    sign(
        os.path.join(
            path,
            "lib",
            "onionshare",
            "resources",
            "tor",
            "meek-client.exe",
        )
    )
    sign(
        os.path.join(
            path,
            "lib",
            "onionshare",
            "resources",
            "tor",
            "obfs4proxy.exe",
        )
    )
    sign(
        os.path.join(
            path,
            "lib",
            "onionshare",
            "resources",
            "tor",
            "snowflake-client.exe",
        )
    )
    sign(
        os.path.join(
            path,
            "lib",
            "onionshare",
            "resources",
            "tor",
            "webtunnel-client.exe",
        )
    )


@main.command()
@click.argument("path")
def package(path):
    """Build the MSI package"""
    pyproject_filename = os.path.join(
        root, "cli", "pyproject.toml"
    )
    with open(pyproject_filename, "rb") as f:
        pyproject = tomllib.load(f)
        version = pyproject['project']['version']

    msi_package(
        path,
        os.path.join(desktop_dir, "dist", f"OnionShare-win64-{version}.msi"),
        "ed7f9243-3528-4b4a-b85c-9943982e75eb",
        version
    )


# Not the upstream UpgradeCode. A fork MSI that reused it would offer to
# upgrade or replace official OnionShare.
FORK_UPGRADE_CODE = "b0aef5da-7c28-4a9f-a000-11b8392782a7"
FORK_SHORTCUT_COMPONENT_GUID = "60720b89-b5aa-4899-b553-05102a169a6a"
FORK_PRODUCT_NAME = "OnionShare Fork (identity backups)"
UPSTREAM_UPGRADE_CODE = "ed7f9243-3528-4b4a-b85c-9943982e75eb"
FORK_SELFTEST_BASENAMES = (
    "onionshare-fork-selftest",
    "onionshare-fork-selftest.exe",
)


@main.command(name="package-fork-unsigned")
@click.argument("path")
def package_fork_unsigned(path):
    """Build an unsigned fork MSI. Skips insignia and signtool."""
    pyproject_filename = os.path.join(root, "cli", "pyproject.toml")
    with open(pyproject_filename, "rb") as f:
        pyproject = tomllib.load(f)
        version = pyproject["project"]["version"]
    if version != "2.7.2":
        raise SystemExit(
            f"WiX ProductVersion must stay numeric 2.7.2, got {version}"
        )
    if FORK_UPGRADE_CODE.lower() == UPSTREAM_UPGRADE_CODE.lower():
        raise SystemExit("fork UpgradeCode collides with upstream")

    tag = os.environ.get("ONIONSHARE_FORK_TAG", "v2.7.2-fork.1")
    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/") :]
    label = tag[1:] if tag.startswith("v") else tag
    if not label.startswith("2.7.2-fork."):
        raise SystemExit(f"unexpected fork tag label: {label}")

    msi_path = os.path.join(
        desktop_dir, "dist", f"OnionShare-fork-{label}-win64-UNSIGNED.msi"
    )
    print(f"> Fork product name: {FORK_PRODUCT_NAME}")
    print(f"> Fork UpgradeCode: {FORK_UPGRADE_CODE}")
    print("> WiX ProductVersion: 2.7.2")
    print("> insignia: skipped")
    print("> signtool: skipped")
    msi_package(
        path,
        msi_path,
        FORK_UPGRADE_CODE,
        version,
        product_name=FORK_PRODUCT_NAME,
        install_dir_name="OnionShareFork",
        shortcut_name=FORK_PRODUCT_NAME,
        shortcut_description=FORK_PRODUCT_NAME,
        registry_key="Software\\OnionShareFork",
        shortcut_component_guid=FORK_SHORTCUT_COMPONENT_GUID,
        skip_basenames=FORK_SELFTEST_BASENAMES,
        sign_package=False,
    )


if __name__ == "__main__":
    main()
