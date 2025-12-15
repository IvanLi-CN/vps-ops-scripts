# Xray 脚本技术规范与经验总结

本目录脚本用于在常见 Linux 发行版上部署/更新 Xray（VLESS+Reality + Shadowsocks 2022），并尽量兼容“服务器上已存在并正在运行的 Xray 服务”。

## 目标与范围

- 目标：可重复运行（idempotent）、可覆盖部署（覆盖已有配置并让服务生效）、尽量不破坏系统已有服务习惯（默认使用 `xray`）。
- 范围：`xray/setup-xray-vless-ss.sh` 及其生成的配置文件与 systemd/OpenRC 服务文件。

## 设计原则

1. **默认不猜测**：默认服务名使用发行版常见名称 `xray`，其余均通过检测现有服务启动参数推断。
2. **兼容已运行服务**：优先跟随现有 service 的 `ExecStart`（systemd）/`command_args`（OpenRC）里指定的配置路径与格式。
3. **覆盖部署必须生效**：当服务正在运行且配置被更新时，必须重启服务加载新配置。
4. **可交互、可管道执行**：脚本支持 `curl | sh` 场景，提示输入优先从 `/dev/tty` 读取，避免吞掉脚本内容。
5. **失败可诊断**：关键步骤输出必要信息；配置验证失败时输出验证错误，便于定位问题。

## 运行流程（高层）

1. 识别 init 系统（systemd/OpenRC/unknown）。
2. 询问服务名（默认 `xray`）。
3. 安装/确认 `xray` 可用。
4. **启动前状态打印**：输出 OS、init、xray 版本、服务是否存在/是否运行、服务使用的配置路径与格式、当前配置是否“看起来符合预期”以及验证结果。
5. 推断并询问配置路径（默认：优先现有服务使用的 `-c/-config/--config/-confdir`，否则使用 `/usr/local/etc/xray/vless-ss-reality.yaml`）。
6. 推断配置格式（优先现有服务 `-format`，否则按文件扩展名推断）。
7. 写入配置（YAML/JSON 模板），复用既有 secret（除非显式要求重生成）。
8. 使用 `xray run -test` 校验配置。
9. 写入/更新 systemd/OpenRC 服务，并在需要时重启服务使配置立即生效。

## 开发规范（对脚本维护者）

- 以 **POSIX `sh`** 为目标（避免 bashism），保持 `set -eu`。
- 对“探测类命令”（如 `systemctl is-active`、`systemctl cat`）必须使用 `|| true` 或重定向避免在 `set -e` 下误退出。
- 变更任何“配置路径/服务管理逻辑”时，必须考虑：
  - 现有服务正在运行；
  - 现有服务通过 drop-in 覆盖 `ExecStart`；
  - 现有服务使用 JSON/YAML 不同格式；
  - 服务名可能是 `xray` 或自定义名称（允许覆盖，但默认不自创）。
- 输出信息要“够用但不刷屏”：默认只打印结论，错误时打印详细日志/验证输出。

## 经验教训（必须牢记）

- **不要固定写配置路径**：现实中大量服务器的 Xray service 使用 `/etc/xray/config.yaml` 等路径；脚本必须跟随现有服务的 `-config`。
- **systemd `enable --now` 不会重启已运行服务**：覆盖配置后如果不显式 `restart`，服务仍在跑旧配置，等于部署失败。
- **默认服务名应贴近发行版生态**：`xray` 比 `xray-vless-ss` 更符合用户预期，也更利于覆盖已有安装。
- **管道执行要选存在的 shell**：建议 `curl ... | sh` 或下载后执行；避免依赖 `zsh` 等非默认 shell。

## 运维检查建议

- systemd：
  - `systemctl status xray`
  - `systemctl cat xray`
  - `journalctl -u xray -e --no-pager`
- 端口监听：
  - `ss -lntp | rg xray`（或 `netstat -lntp`）
- 配置校验：
  - `xray run -test -c /path/to/config.yaml -format yaml`

