# Smart Unpacker

[中文](./README.md) | [English](./README.en.md) | [日本語](./README.ja.md)

Smart Unpacker は、AI の支援を受けて開発された Windows 向けの Python 製コマンドライン解凍ツールです。

偽装アーカイブ、入れ子アーカイブ、分割アーカイブ、パスワード付きアーカイブ、自己解凍ファイルを一括処理するためのツールで、検出、検証、解凍、後片付けをできるだけ一貫した流れで実行します。

Windows Explorer の右クリックメニューに登録して使う方法を推奨します。登録後は、フォルダーまたはディレクトリ内の空白部分を右クリックして起動し、複数のパスワードを入力すると自動で試行できます。処理に成功した元アーカイブはごみ箱へ移動され、解凍結果が単一の子ディレクトリだけを含む場合は自動でフラット化されます。

## 主な用途

- フォルダー内のさまざまなアーカイブをまとめて解凍する。
- 拡張子が偽装されている、または欠落しているアーカイブを検出する。
- 分割アーカイブ、入れ子アーカイブ、自己解凍ファイルを処理する。
- コマンドライン指定のパスワード、パスワードファイル、内蔵の高頻度パスワードを自動で試行する。
- 解凍後に元アーカイブを整理し、1 階層だけ余分なディレクトリ構造を簡略化する。

## クイックスタート

Releases のビルド済みパッケージを使う方法を推奨します。

1. Release アーカイブをダウンロードし、固定のディレクトリに展開します。
2. 右クリックメニューを登録します。

```powershell
.\scripts\register_context_menu.ps1
```

3. Explorer でフォルダーまたはディレクトリ内の空白部分を右クリックし、`Smart Unpacker` を選択します。
4. 右クリックメニューを削除する場合は、次を実行します。

```powershell
.\scripts\unregister_context_menu.ps1
```

`builtin_passwords.txt` は内蔵パスワード一覧です。毎回よく使うパスワードを手入力したくない場合は、このファイルに 1 行 1 パスワードで追加しておくと、解凍時に自動で試行されます。

## 設定

メイン設定ファイルは `smart_unpacker_config.json` です。

よく使う設定:

- `basic.min_inspection_size_bytes`: 検査対象にする最小ファイルサイズです。これより小さいファイルは無視されます。既定値は `1048576`、つまり `1 MB` です。値を大きくすると大量の小さなファイルを走査する負荷を減らせます。値を小さくすると、より小さな偽装アーカイブも検出しやすくなります。
- `basic.scheduler_profile`: 並列実行戦略です。通常は `auto` で十分です。`aggressive` は性能重視、`conservative` はプロセス数が多すぎる場合や他の作業への影響を抑えたい場合に向いています。
- `advanced.scheduler`: 並列実行の詳細設定です。既定値はすべて `0` で、`scheduler_profile` に従うことを意味します。具体的な値を設定すると、対応する profile の挙動を上書きします。

## コマンド

- `inspect`: ファイルまたはディレクトリを再帰的に検査し、各ファイルの判定結果、ヒット理由、解凍推奨かどうかを出力します。
- `scan`: 処理可能なアーカイブをタスク単位で集計し、解凍前にスキャン結果を確認できます。
- `extract`: スキャン、パスワード試行、アーカイブ検証、解凍、後処理を実行し、システム負荷に応じて並列度を動的に調整します。
- `passwords`: コマンドライン入力、パスワードファイル、内蔵の高頻度パスワードを含む、最終的に試行されるパスワード一覧を表示します。

共通オプション:

- `--json`: 結果を JSON 形式で出力します。
- `--quiet`: ターミナル出力を減らします。
- `--verbose`: より詳細な情報を出力します。
- `--pause-on-exit`: 終了前にキー入力を待ちます。右クリックメニューから使う場合に便利です。

パスワード関連オプション:

- `-p, --password`: 解凍パスワードを指定します。複数回指定できます。
- `--password-file`: パスワードファイルを指定します。1 行 1 パスワードとして読み込みます。
- `--prompt-passwords`: ターミナル上で対話的にパスワード一覧を入力します。
- `--no-builtin-passwords`: 内蔵の高頻度パスワードを無効化します。

## ローカル実行

1. Python 3 をインストールします。
2. ローカル開発環境を初期化します。

```powershell
.\scripts\setup_windows_dev.ps1
```

このスクリプトは以下を行います。

- `.venv` を作成します。
- `requirements.txt` の実行時依存をインストールします。
- `tools` ディレクトリで不足している 7-Zip 実行コンポーネントを補完します。

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

GitHub Actions で使われる CI テスト入口:

```powershell
.\scripts\run_ci_tests.ps1
```

テスト用のローカルパスとツール検索ルールは次のファイルで管理されています。

```text
tests/test_config.json
```

現在の合成サンプルは、RPG Maker、Ren'Py、Godot、NW.js、Electron のディレクトリ意味ファミリーをカバーしています。

フルテスト内の RAR サンプルには `Rar.exe` が必要です。見つからない場合、RAR に依存するサンプル生成部分は自動的にスキップされます。`Rar.exe` のパスは `tests/test_config.json` で設定できます。

## 依存関係とビルド

依存関係ファイル:

- 実行時依存: `requirements.txt`
- ビルド依存: `requirements-build.txt`
- 7-Zip 実行コンポーネント: 不足している場合、ローカル初期化スクリプトとビルドスクリプトが自動でダウンロードして補完します。

Windows リリースパッケージをビルドします。

```powershell
.\scripts\build_windows.ps1
```

ビルド処理では自動的にテストも実行され、プロジェクト変更によって通常ファイルが誤って削除されることを防ぎます。

オプション引数:

- `-SkipTests`: テストを省略し、パッケージング経路のみを確認します。
- `-Clean`: ビルド用仮想環境を追加で掃除してから再構築します。
- `-Version <string>`: リリース名に使う既定のバージョン文字列を上書きします。

ビルド完了後に生成されるもの:

- `dist/SmartUnpacker/`: そのまま実行できる配布ディレクトリ。
- `release/*.zip`: 配布しやすい zip パッケージ。

## 注意事項

このソフトウェアは複雑なケースでテストされていますが、ファイルの誤削除が絶対に起きないことを保証するものではありません。データが復元可能、またはバックアップ済みであることを確認してから使用してください。使用によって発生したファイル損失は利用者自身の責任となります。

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
