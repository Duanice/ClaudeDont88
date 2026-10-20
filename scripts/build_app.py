#!/usr/bin/env python3
"""Build an ad-hoc preview, or a provisioned development bundle. Never installs it."""
import argparse
import datetime
import pathlib
import plistlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_ID = "io.github.duanice.ClaudeDont88"
EXT_ID = APP_ID + ".filter"
CAPABILITY = "content-filter-provider-systemextension"


def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)


def write_plist(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value))


def validate_profile(path, team, bundle_id, host):
    raw = subprocess.check_output(["security", "cms", "-D", "-i", str(path)])
    profile = plistlib.loads(raw)
    entitlements = profile.get("Entitlements", {})
    if profile.get("ExpirationDate", datetime.datetime.min) <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        raise ValueError("Provisioning profile has expired")
    if team not in profile.get("TeamIdentifier", []):
        raise ValueError("Profile does not match the requested team")
    if entitlements.get("com.apple.application-identifier") != team + "." + bundle_id:
        raise ValueError("Profile must have the exact application identifier: " + bundle_id)
    if CAPABILITY not in entitlements.get("com.apple.developer.networking.networkextension", []):
        raise ValueError("Profile lacks the content-filter system-extension entitlement")
    if host and not entitlements.get("com.apple.developer.system-extension.install"):
        raise ValueError("Host profile lacks system-extension.install")
    return entitlements


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity")
    parser.add_argument("--team")
    parser.add_argument("--app-profile", type=pathlib.Path)
    parser.add_argument("--filter-profile", type=pathlib.Path)
    args = parser.parse_args()
    signing = [args.identity, args.team, args.app_profile, args.filter_profile]
    if any(signing) and not all(signing):
        parser.error("Signed builds require --identity, --team, --app-profile and --filter-profile")
    if args.identity == "-":
        parser.error("Provisioned builds require a real signing identity")
    if args.identity:
        for profile, bid, host in [(args.app_profile, APP_ID, True),
                                   (args.filter_profile, EXT_ID, False)]:
            validate_profile(profile, args.team, bid, host)
    run("swift", "build", "-c", "release")
    binaries = pathlib.Path(subprocess.check_output(
        ["swift", "build", "-c", "release", "--show-bin-path"], cwd=ROOT, text=True).strip())
    output = ROOT / "build"
    app = output / "ClaudeDont88.app"
    if app.exists():
        shutil.rmtree(app)
    ext = app / "Contents/Library/SystemExtensions" / (EXT_ID + ".systemextension")
    for folder in [app / "Contents/MacOS", app / "Contents/Helpers", ext / "Contents/MacOS"]:
        folder.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binaries / "ClaudeDont88", app / "Contents/MacOS/ClaudeDont88")
    shutil.copy2(binaries / "guard-probe", app / "Contents/Helpers/guard-probe")
    shutil.copy2(binaries / "guard-runtime", app / "Contents/Helpers/guard-runtime")
    shutil.copy2(binaries / "GuardFilter", ext / "Contents/MacOS/GuardFilter")
    common = {
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleShortVersionString": "0.2.0",
        "CFBundleVersion": "1",
        "LSMinimumSystemVersion": "15.0",
    }
    write_plist(app / "Contents/Info.plist", dict(common, **{
        "CFBundleIdentifier": APP_ID, "CFBundleExecutable": "ClaudeDont88",
        "CFBundleName": "ClaudeDont88", "CFBundlePackageType": "APPL",
        "NSHighResolutionCapable": True, "LSUIElement": True,
        "NSSystemExtensionUsageDescription": "验证目标程序的网络连接过滤；此版本不提供完整防泄漏保证。",
    }))
    write_plist(ext / "Contents/Info.plist", dict(common, **{
        "CFBundleIdentifier": EXT_ID, "CFBundleExecutable": "GuardFilter",
        "CFBundleName": "ClaudeDont88 Prototype Filter", "CFBundlePackageType": "SYSX",
        "NetworkExtension": {
            "NEProviderClasses": {"com.apple.networkextension.filter-data": "FilterDataProvider"}
        },
    }))
    identity = args.identity or "-"
    sign_args = ["codesign", "--force", "--sign", identity]
    if args.identity:
        sign_args += ["--options", "runtime", "--timestamp"]
        for bundle, bid, profile, host in [
            (app, APP_ID, args.app_profile, True), (ext, EXT_ID, args.filter_profile, False)
        ]:
            shutil.copy2(profile, bundle / "Contents/embedded.provisionprofile")
            entitlements = {
                "com.apple.application-identifier": args.team + "." + bid,
                "com.apple.developer.team-identifier": args.team,
                "com.apple.developer.networking.networkextension": [CAPABILITY],
            }
            if host:
                entitlements["com.apple.developer.system-extension.install"] = True
            else:
                entitlements["com.apple.security.app-sandbox"] = True
            write_plist(output / (bid + ".entitlements"), entitlements)
    run(*sign_args, "--identifier", APP_ID + ".probe", str(app / "Contents/Helpers/guard-probe"))
    run(*sign_args, "--identifier", APP_ID + ".runtime", str(app / "Contents/Helpers/guard-runtime"))
    for bundle, bid in [(ext, EXT_ID), (app, APP_ID)]:
        entitlements = ["--entitlements", str(output / (bid + ".entitlements"))] if args.identity else []
        run(*sign_args, *entitlements, str(bundle))
    run("codesign", "--verify", "--deep", "--strict", str(app))
    print(app)
    print("PROVISIONED EXPERIMENT — live enforcement still needs qualification" if args.identity
          else "PREVIEW ONLY — no privileged entitlements; extension cannot be activated")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
