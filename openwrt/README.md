# OpenWrt 官方原生构建指南 (Official OpenWrt Package Build Guide)

本项目包含符合 OpenWrt 官方规范的标准 Package Makefile：
- `openwrt/package/p2ptap`：核心 P2P TAP VPN 节点程序与 `procd` 系统服务
- `openwrt/package/luci-app-p2ptap`：OpenWrt LuCI WebUI 管理界面

---

## 🛠️ 官方推荐构建方法 (Official Recommended Build Methods)

### 方法一：使用 GitHub Actions 官方 SDK (`openwrt/gh-action-sdk`)
OpenWrt 官方团队维护了 GitHub Actions 专用构建 Action [openwrt/gh-action-sdk](https://github.com/openwrt/gh-action-sdk)。

在 workflow `.github/workflows/release.yml` 中使用官方 Action：
```yaml
- name: Build OpenWrt Packages via Official OpenWrt SDK
  uses: openwrt/gh-action-sdk@v1
  with:
    archetype: x86/64  # 或 aarch64_cortex-a53, mipsel_24kc 等官方架构名
    env: |
      CONFIG_PACKAGE_p2ptap=m
      CONFIG_PACKAGE_luci-app-p2ptap=m
```

---

### 方法二：使用本地 OpenWrt 官方 SDK 原生命令行构建

可以在 Linux / macOS 环境下使用 OpenWrt 官方 SDK 独立编译安装包：

```bash
# 1. 运行一键构建脚本 (自动下载 SDK、配置 feeds 并调用原生 make 编译)
./scripts/build_openwrt_sdk.sh

# 或者手动执行以下标准步骤：

# 2. 下载对应架构的 OpenWrt 官方 SDK (以 23.05.5 x86_64 为例)
wget https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-sdk-23.05.5-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz
tar -xf openwrt-sdk-*.tar.xz && cd openwrt-sdk-*

# 3. 更新并安装依赖 Feeds (包含 golang 和 luci)
./scripts/feeds update -a
./scripts/feeds install -a

# 4. 将 p2ptap 的 package 拷贝至 SDK 目录
cp -r /path/to/p2ptap/openwrt/package/* package/

# 5. 调用 OpenWrt 官方 Buildroot 进行原生编译
make package/p2ptap/compile V=s
make package/luci-app-p2ptap/compile V=s
```

编译产物位于 `bin/packages/<arch>/base/` 和 `bin/packages/<arch>/luci/` 中。

---

### 方法三：集成进 OpenWrt 完整源码 (Buildroot) 编译固件

如果你正在自行编译完整 OpenWrt 路由器固件：

```bash
cd openwrt
# 放置 package 源码
cp -r /path/to/p2ptap/openwrt/package/* package/

# 更新 feeds 并配置
./scripts/feeds update -a && ./scripts/feeds install -a
make menuconfig
# 在 menuconfig 菜单中勾选:
#   Network -> VPN -> p2ptap
#   LuCI -> Applications -> luci-app-p2ptap

# 开始编译
make -j$(nproc)
```
