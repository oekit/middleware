# Changelog — oekit/middleware

由 ekit v0.34.0（git.enjoye.top/enjoydream/ekit，冻结维护）拆分而来。所有 notable 变更记录如下。

## [v0.2.0] — 2026-10-15

可观测性统一轮。

### Breaking
- `DefaultMiddleware` **不再包含 Prometheus 指标中间件**，栈变为
  TraceID → Recovery → Response → AccessLog；`StackConfig` 删除
  `ServiceName` / `Namespace` / `Registry` 三个指标专用字段（只留 `SkipPaths`）

### Fixed
- `PrometheusConfig.Registry` 缺省语义修正：nil 时使用 ekit 统一注册表
  `metrics.Registry`（原先 nil = `prom.DefaultRegisterer`，指标会落在一个
  `/metrics` 端点不暴露的注册表里静默丢失；该兜底原先只在 DefaultMiddleware
  组装路径生效，显式拼装时踩坑）

### 迁移
- 需要 HTTP 指标的服务在标准栈前显式拼装：
  `pm := mw.NewPrometheusMetrics(mw.PrometheusConfig{...}); h.Use(pm.Middleware())`
- 原 `StackConfig{ServiceName/Namespace/Registry}` 字段值移入 `PrometheusConfig`

## [v0.1.9] — 2026-10-15

- v0.1.9

## [v0.1.8] — 2026-10-15

- v0.1.8

## [v0.1.7] — 2026-10-15

- v0.1.7

## [v0.1.6] — 2026-10-15

- v0.1.6

## [v0.1.5] — 2026-10-15

- v0.1.5

## [v0.1.4] — 2026-10-15

- v0.1.4

## [v0.1.3] — 2026-10-15

- v0.1.3

## [v0.1.2] — 2026-10-15

- v0.1.2

## [v0.1.1] — 2026-10-15

- v0.1.1

## [v0.1.0] — 2026-10-15

- v0.1.0
