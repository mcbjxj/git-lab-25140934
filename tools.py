import subprocess
import os
import tempfile
import shutil

# ======================== 路径配置 ========================
R2_PATH = "/usr/bin/r2"
# Ghidra 无头模式脚本路径，请根据你的实际解压位置调整
GHIDRA_HEADLESS = os.path.expanduser("~/ghidra_11.0.3/support/analyzeHeadless")
CHALLENGE_PATH = os.path.abspath("targets/challenge")

# ======================== radare2 白名单 ========================
ALLOWED_R2_CMDS = {
    "aaa", "aa", "afl", "afla", "aflq", "aflm",
    "pdf", "pdr", "pd", "px", "pxa", "pxw", "pxq",
    "iz", "izz", "iI", "ii", "ie", "iE", "is", "iS", "il",
    "S", "s", "?e", "e", "?",             # e 只读查询是安全的
    "axt", "axf", "af", "afll", "afi",
}

# ======================== 内部状态 ========================
_binary_analyzed = False

def ensure_analysis():
    """预热分析，确保后续 r2 命令能直接获得分析结果。"""
    global _binary_analyzed
    if not _binary_analyzed:
        # 运行一次完整分析，忽略输出
        subprocess.run(
            [R2_PATH, "-q", "-c", "aaa", "-c", "quit", CHALLENGE_PATH],
            capture_output=True, timeout=60
        )
        _binary_analyzed = True

def run_r2_command(cmd: str) -> str:
    """
    执行只读 radare2 命令，返回输出字符串。
    命令会自动附带 'aaa;' 前缀，确保每次调用都有分析数据。
    """
    cmd_base = cmd.strip().split()[0]
    if cmd_base not in ALLOWED_R2_CMDS:
        return (f"Error: command '{cmd_base}' not allowed. "
                f"Available commands: {sorted(ALLOWED_R2_CMDS)}")

    # 自动在用户命令前加入分析步骤（除非命令本身就是 aaa）
    if cmd_base == "aaa":
        full_cmd = cmd
    else:
        full_cmd = f"aaa;{cmd}"

    try:
        result = subprocess.run(
            [R2_PATH, "-q", "-c", full_cmd, CHALLENGE_PATH],
            capture_output=True, text=True, timeout=30
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # 如果有标准错误输出，一并返回以便排查
        if stderr:
            return f"r2 stderr: {stderr}\nstdout: {stdout if stdout else '(empty)'}"

        # 限制输出长度，避免 token 爆炸
        if len(stdout) > 1500:
            stdout = stdout[:1500] + "\n... [truncated]"
        return stdout if stdout else "(no output)"

    except subprocess.TimeoutExpired:
        return "r2 command timed out (>30s)"
    except Exception as e:
        return f"r2 error: {str(e)}"

def decompile_function(address_or_name: str) -> str:
    """
    使用 Ghidra 无头模式反编译指定函数，返回伪 C 代码。
    参数可以是地址（如 '0x401130'）或函数名（如 'main'）。
    """
    # Ghidra 分析脚本（Java）
    script = """#@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

DecompInterface decomp = new DecompInterface();
decomp.openProgram(currentProgram);
Function func = null;
try {
    Address addr = currentProgram.getAddressFactory().getAddress("ADDR_OR_NAME");
    func = currentProgram.getFunctionManager().getFunctionContaining(addr);
} catch (Exception e) {
    // 不是有效地址，尝试按名称查找
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        if (f.getName().equals("ADDR_OR_NAME")) {
            func = f;
            break;
        }
    }
}
if (func == null) {
    println("Function not found: ADDR_OR_NAME");
    return;
}
var res = decomp.decompileFunction(func, 30, monitor);
if (res != null && res.decompileCompleted()) {
    println(res.getDecompiledFunction().getC());
} else {
    println("Decompilation failed");
}
""".replace("ADDR_OR_NAME", address_or_name)

    # 将脚本写入临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
        f.write(script)
        script_path = f.name

    project_dir = tempfile.mkdtemp(prefix="ghidra_proj_")
    try:
        cmd = [
            GHIDRA_HEADLESS, project_dir, "TempProject",
            "-import", CHALLENGE_PATH,
            "-postScript", script_path,
            "-scriptPath", os.path.dirname(script_path),
            "-deleteProject"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # 过滤掉 Ghidra 的 INFO/DEBUG/WARN 日志，只保留脚本输出
        lines = []
        for line in result.stdout.splitlines():
            if line.startswith("INFO") or line.startswith("DEBG") or line.startswith("WARN"):
                continue
            lines.append(line)
        cleaned = "\n".join(lines).strip()

        if len(cleaned) > 2000:
            cleaned = cleaned[:2000] + "\n... [truncated]"
        return cleaned if cleaned else "Decompilation produced no output"

    except subprocess.TimeoutExpired:
        return "Ghidra decompilation timed out (>120s)"
    except Exception as e:
        return f"Ghidra error: {str(e)}"
    finally:
        # 清理临时文件
        os.unlink(script_path)
        shutil.rmtree(project_dir, ignore_errors=True)
