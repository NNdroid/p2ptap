# p2ptap OpenWrt feed

Source feed (SDK / Buildroot feeds.conf.default):

    src-git p2ptap https://github.com/NNdroid/p2ptap.git;openwrt-feed

Then run `./scripts/feeds update p2ptap` and `./scripts/feeds install -a -p p2ptap`.

Signed APK repositories are published after successful OpenWrt Signed APK Feed runs.
Repository layout: `releases/<OpenWrt release>/<target>/<subtarget>/packages.adb`.

On an APK-based router, after the repository for your release/target has been published:

```sh
. /etc/openwrt_release
BASE=https://raw.githubusercontent.com/NNdroid/p2ptap/openwrt-feed
mkdir -p /etc/apk/keys /etc/apk/repositories.d
wget -O /etc/apk/keys/p2ptap-feed.pem "$BASE/p2ptap-feed.pem"
printf '%s\n' "$BASE/releases/$DISTRIB_RELEASE/$DISTRIB_TARGET/packages.adb" > /etc/apk/repositories.d/p2ptap.list
apk update
apk add p2ptap luci-app-p2ptap luci-i18n-p2ptap-zh-cn
```
