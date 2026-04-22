# Smart Unpacker

[中文](./README.md) | [English](./README.en.md) | [日本語](./README.ja.md)

Smart Unpacker は、AI の支援を受けて開発された Windows 向けの Python 製コマンドライン解凍ツールです。
主に、偽装アーカイブ、入れ子アーカイブ、分割アーカイブ、パスワード付きアーカイブ、自己解凍ファイルを一括処理するために使われ、検出、検証、解凍、後片付けをできるだけ統一されたフローで実行します。
また、Windows の右クリックメニューにも登録できます。フォルダーやフォルダー背景の右クリックメニューから起動でき、複数のパスワードを入力すると自動で試行し、解凍後は元のアーカイブを直接ごみ箱へ移動し、単一の子ディレクトリは自動でフラット化します。

# 使い方

Windows の右クリックメニューから起動する方法を推奨します。
Releases からビルド済みパッケージをダウンロードすることも、説明に従ってソースからビルドすることも、ソースのまま直接実行することもできます。
Release の zip をダウンロードしたら、固定の場所に展開してください。`scripts/register_context_menu.ps1` を実行すると右クリックメニューを登録でき、`scripts/unregister_context_menu.ps1` を実行すると解除できます。
`builtin_passwords.txt` には内蔵パスワード一覧が入っています。毎回パスワードを入力したくない場合は、よく使うパスワードをここに追加しておけば、自動で試行できます。

## 設定ファイル

`smart_unpacker_config.json` が設定ファイルです。

`min_inspection_size_bytes` は、プログラムが検査対象として扱う最小アーカイブサイズです。これより小さいファイルは認識・処理されません。値を大きくすると大量の小さな雑多ファイルによる性能負荷を減らせます。小さくすると小型の偽装アーカイブも検出しやすくなります。既定値は `1 MB` です。

`basic` 配下は一般ユーザー向けの基本設定です。

`scheduler_profile` は並列実行戦略を制御します。通常は `auto` で十分です。より積極的な性能重視の設定にしたい場合は `aggressive`、動作中のプロセス数を抑えて他の作業への影響を減らしたい場合は `conservative` を使ってください。

`advanced.scheduler` 配下は詳細な並列制御用です。既定ではすべて `0` で、選択した `scheduler_profile` の設定が適用されます。ここに具体的な値を入れると、対応する profile の挙動を上書きします。

## 機能概要

- `inspect`: ファイルまたはディレクトリを再帰的に調べ、各ファイルの判定結果、ヒット理由、解凍推奨かどうかを出力します。
- `scan`: 処理可能なアーカイブをタスク単位で集計し、解凍前にスキャン結果を確認できます。
- `extract`: スキャン、パスワード試行、アーカイブ検証、解凍、後処理を実行し、システム負荷に応じて並列度を動的に調整します。
- `passwords`: コマンドライン入力や内蔵の高頻度パスワードを含め、実際に試行対象となるパスワード一覧を表示します。
- Windows 統合: PowerShell スクリプトで Explorer の右クリックメニューに登録できます。
- Windows ビルド: ビルドスクリプトが不足している 7-Zip 実行コンポーネントを自動補完し、配布用ディレクトリと zip を生成します。

## ローカル実行

1. Python 3 をインストールします。
2. ローカル開発環境を初期化します。

```powershell
.\scripts\setup_windows_dev.ps1
```

このスクリプトは以下を行います。

- `.venv` を作成
- `requirements.txt` にある実行時依存をインストール
- `tools` ディレクトリ内で不足している 7-Zip コンポーネントを自動で補完

3. CLI を実行します。

```powershell
python smart-unpacker.py <command> [options] [paths...]
```

例:

```powershell
python smart-unpacker.py inspect .\fixtures
python smart-unpacker.py scan .\archives
python smart-unpacker.py extract -p "secret" .\archives\sample.zip
python smart-unpacker.py extract --prompt-passwords .\archives
python smart-unpacker.py passwords
```

## テスト

ロジック全体の受け入れテスト:

```powershell
.\run_acceptance_tests.ps1
```

### 依存関係

- 実行時依存: `requirements.txt`
- ビルド依存: `requirements-build.txt`
- 7-Zip 実行コンポーネント: 不足している場合、ビルドスクリプトとローカル初期化スクリプトが自動でダウンロードして補完

### ビルド

```powershell
.\scripts\build_windows.ps1
```

ビルド処理では自動的にテストも実行され、プロジェクト変更によって通常ファイルが誤って削除されないよう確認します。

オプション引数:

- `-SkipTests`: テストを省略し、パッケージング経路のみを確認します。
- `-Clean`: ビルド用仮想環境を追加で掃除してから再構築します。
- `-Version <string>`: リリース名に使う既定のバージョン文字列を上書きします。

ビルド完了後に生成されるもの:

- `dist/SmartUnpacker/`: そのまま実行できる配布ディレクトリ
- `release/*.zip`: 配布しやすい zip パッケージ

### 注意事項

このソフトウェアは複雑なケースでテストされていますが、ファイルの誤削除が絶対に起きないことを保証するものではありません。利用は自己責任でお願いします。開発者はファイル損失について責任を負いません。
