# p2ptap OpenWrt 25.12 APK feed

仅支持 OpenWrt 25.12 系列；CI 当前固定使用 25.12.5 官方 SDK，输出签名 APK 包和 `packages.adb`，不构建旧版本 IPK。

## 路由器添加自定义源

以 OpenWrt 25.12.5 x86/64 为例，先安装 feed 公钥，然后添加仓库：

```sh
BASE=https://raw.githubusercontent.com/NNdroid/p2ptap/openwrt-feed
mkdir -p /etc/apk/keys /etc/apk/repositories.d
wget -O /etc/apk/keys/p2ptap-feed.pem "$BASE/p2ptap-feed.pem"
printf '%s\n' "$BASE/releases/25.12.5/x86/64/packages.adb" > /etc/apk/repositories.d/p2ptap.list
apk update
apk add p2ptap luci-app-p2ptap luci-i18n-p2ptap-zh-cn
```

对应自定义源地址：

`https://raw.githubusercontent.com/NNdroid/p2ptap/openwrt-feed/releases/25.12.5/x86/64/packages.adb`

其他目标使用 `releases/25.12.5/<target>/<subtarget>/packages.adb`；须与固件的 `/etc/openwrt_release` 一致。CI 构建 x86/64、armsr/armv8、armsr/armv7、rockchip/armv8、mediatek/filogic、ramips/mt7621、ath79/generic。签名仓库首次构建并发布成功后这些地址才可使用。客户端无需 `--allow-untrusted`。

## 自动发布

`OpenWrt 25.12 Signed APK Feed` 支持标签、main 或当前开发分支的代码推送、手动运行以及 Release 工作流调用。各目标共用一次解析的包版本；所有目标成功并通过签名检查后，才更新 `openwrt-feed` 分支。发布保留其他 OpenWrt 版本目录。

签名配置位于 **NNdroid/p2ptap** 仓库的 Settings → Secrets and variables → Actions：

- Secret `OPENWRT_FEED_SIGNING_KEY_B64`：Base64 编码的无密码 EC P-256 私钥。
- Variable `OPENWRT_FEED_PUBLIC_KEY_B64`：匹配的公钥 Base64。

缺少配置、配对不符、构建或签名校验失败均阻止发布。私钥不会进入提交或上传 artifact。APK 包及索引使用同一稳定密钥签名，客户端仅需安装上述公钥。

`PKG_VERSION` 去掉发布标签前导 `v`；`PKG_RELEASE` 使用源提交的完整 Git 历史累计数，核心、LuCI 和翻译包一致。浅克隆会报错，历史重写可能改变累计数。

## 本地 SDK 构建

Linux 下安装 SDK host 依赖后，在完整历史的项目 checkout 中运行：

```sh
OPENWRT_TARGET=x86 OPENWRT_SUBTARGET=64 VERSION=v1.0.20261001 bash scripts/build_openwrt_sdk.sh
```

脚本从官方下载 25.12.5 SDK 并检查 SHA256，安装 feeds，构建 APK。项目需要 Go 1.27，包显式依赖 SDK packages feed 的 `golang1.27/host`。源码固定到当前提交，WebUI 嵌入资源会完整保留。

## 源码 feed

SDK / Buildroot `feeds.conf.default`：

```text
src-git p2ptap https://github.com/NNdroid/p2ptap.git;openwrt-feed
```

然后运行 `./scripts/feeds update p2ptap` 和 `./scripts/feeds install -a -p p2ptap`。

## 检查

```sh
node scripts/test_openwrt_version.cjs
node scripts/test_openwrt_status.cjs
bash scripts/test_openwrt_feed_keys.sh
```

LAN 子网互联仍需配置 TAP 网络接口及对应防火墙转发规则，再在 LuCI 中配置宣告网段与允许接收的节点。
