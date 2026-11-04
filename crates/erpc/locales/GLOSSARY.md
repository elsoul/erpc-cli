<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Glossary

One term per concept, in every catalog of a language (here and in
`crates/erpc-ai/locales/`). Settled in the review of 2026-11-02; change a
term here and in every file at once.

Never translated: command names, flags, `erpc.toml` keys, env names,
paths, ERPC, VPS, Unlimited RPC, Shreds, gRPC, ERPC Global Storage,
1Password, restic, systemd, Solana, EURC.

| English | ja | zh | ru |
|---|---|---|---|
| app | アプリ | 应用 | приложение («приложение {name}») |
| worker (the process) | ワーカー | worker | воркер |
| environment | 環境 | 环境 | окружение |
| server | サーバー | 服务器 | сервер |
| this machine | このマシン | 本机 | эта машина |
| deploy | デプロイ | 部署 | развернуть / развёртывание |
| release | リリース | 版本 | релиз |
| roll back | ロールバック | 回滚 | откатить |
| healthy | 正常 | 健康 | работоспособен |
| trading key | 取引用の鍵 | 交易密钥 | торговый ключ |
| key / public key | 鍵 / 公開鍵 | 密钥 / 公钥 | ключ / публичный ключ |
| host key | ホスト鍵 | 主机密钥 | ключ хоста |
| access key / API key | アクセスキー / API キー | 访问密钥 / API 密钥 | ключ доступа / API-ключ |
| secret setting | シークレット | 机密设置 | секретная настройка |
| store (where kept) | 保管先 | 保存位置 | хранилище |
| vault (1Password) | 保管庫 | 保险库 | хранилище |
| 1Password item | アイテム | 项目 | элемент |
| keychain | キーチェーン | 钥匙串 | связка ключей |
| wallet / hot wallet | ウォレット / ホットウォレット | 钱包 / 热钱包 | кошелёк / горячий кошелёк |
| revoke | 取り消す | 吊销 | отозвать |
| hourly | 時間課金 | 按小时计费 | с почасовой оплатой |
| charged by the hour | 時間単位で課金される | 正在按小时计费 | оплачивается почасово |
| start (a paid product) | 開始する | 开通 | запустить |
| end (a paid product) | 終了する | 终止 | завершить |
| data line | データ回線 / 回線 | 数据线路 / 线路 | линия данных / линия (f.) |
| take up (on record) | 引き継ぐ | 接管 | подхватить |
| on record / off the record | 記録に残る / 記録から外す | 已记录 / 从记录中移除 | в записях / убрать из записей |
| plan / product id | プラン / 商品 ID | 套餐 / 产品 ID | тариф / ID продукта |
| ERPC Credit | ERPC クレジット | ERPC 积分 | кредиты ERPC |
| dashboard | ダッシュボード | 控制面板 | панель управления |
| console (`erpc ai`) | コンソール | 控制台 | консоль |
| conversation | 会話 | 对话 | разговор |
| remembered fact | 記憶 | 记忆 | запомненный факт |
| region | リージョン | 区域 | регион |
| firewall / allow list | ファイアウォール / 許可リスト | 防火墙 / 允许列表 | файрвол / список разрешённых |
| let in | 接続を許可する | 允许…接入 | открыть доступ |
| snapshot / backup | スナップショット / バックアップ | 快照 / 备份 | снимок / резервная копия |
| default (in help) | 既定 | 默认 | по умолчанию |
| sign in | サインイン | 登录 | войти |

Style: Japanese help in the dictionary form (〜する), messages in the polite
form (〜しました); Chinese and Japanese full-width punctuation except the
`Usage:`-style headings, whose colon clap adds; Russian errors and hints
start lowercase as in English, `ё` written.

Open questions for a human: whether ERPC Credit stays untranslated in zh
and ru (积分 reads as loyalty points, кредит as a loan); whether «воркер» or
Latin "worker" in Russian; the dashboard's own words once it has
translations.
