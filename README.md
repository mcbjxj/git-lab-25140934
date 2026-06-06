# ReAct Agent 静态分析 - 环境说明

## 1. Python 依赖
pip install -r requirements.txt

## 2. radare2 路径
- 默认安装路径：`/usr/bin/r2`
- 安装方法：`sudo apt install radare2`
- 本项目 `tools.py` 中已配置为 `R2_PATH = "/usr/bin/r2"`，若你的系统不同，请修改该变量。

## 3. Ghidra 路径（必须与 tools.py 一致）
- 本项目使用 Ghidra 11.0.3 无头模式，路径为：
  `~/ghidra_11.0.3/support/analyzeHeadless`
- 如果你将 Ghidra 解压到其他位置，请修改 `tools.py` 开头的 `GHIDRA_HEADLESS` 变量。
- 确保已安装 Java 17+：`sudo apt install openjdk-17-jdk`
- 下载 Ghidra 后，解压并验证：
  ```bash
  unzip ghidra_11.0.3_PUBLIC_20240410.zip -d ~/ghidra_11.0.3
  ls ~/ghidra_11.0.3/support/analyzeHeadless   # 确认存在
