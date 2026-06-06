import json
import os
from openai import OpenAI
from tools import ensure_analysis, run_r2_command, decompile_function

# DeepSeek 配置
client = OpenAI(
    api_key="sk-68098***************8443a42a",
    base_url="https://api.deepseek.com/v1",
)
MODEL = "deepseek-chat"

tools = [
    {
        "type": "function",
        "function": {
            "name": "r2",
            "description": "Execute a read-only radare2 command on the challenge binary. Available commands include: aaa, afl, pdf, iz, ii, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The r2 command, e.g. 'afl', 'pdf @ 0x401000', 'iz', 'ii'"
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra",
            "description": "Decompile a function at the given address or name, returning C pseudocode.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address_or_name": {
                        "type": "string",
                        "description": "Function address (e.g. '0x401000') or name (e.g. 'main')"
                    }
                },
                "required": ["address_or_name"]
            }
        }
    }
]

SYSTEM_PROMPT = """You are a static analysis agent for a Linux x86_64 ELF binary named 'challenge'.
The binary has been pre-analyzed, and you will receive function list, strings, and imports below.
Your tools are:
- r2: execute radare2 read-only commands (e.g., 'pdf @ 0x401000', 'iz', 'ii').
- ghidra: decompile a function.

Work strictly in this order:
1. From the provided info, identify suspicious functions that call dangerous imports (gets, system, strcpy, etc.) and reference strings like "/bin/sh".
2. Disassemble the suspicious function with r2 (pdf @ address).
3. Decompile it with ghidra to confirm the vulnerability (buffer overflow, command injection, etc.).
4. When you are certain, output ONLY the final JSON object, no additional text.

Final answer format exactly:
{"vuln_type": "...", "location": "...", "cause": "..."}
Do NOT include any explanation outside the JSON."""

def process_tool_call(tool_call):
    name = tool_call.function.name
    args = json.loads(tool_call.function.arguments)
    if name == "r2":
        return run_r2_command(args["command"])
    elif name == "ghidra":
        return decompile_function(args["address_or_name"])
    else:
        return "Unknown tool"

def main():
    # 1. 确保二进制已分析
    ensure_analysis()

    # 2. 获取初步信息
    funcs = run_r2_command("afl") or "(none)"
    strs = run_r2_command("iz") or "(none)"
    imps = run_r2_command("ii") or "(none)"

    init_info = (
        "Here is the initial analysis of the binary:\n"
        f"Functions:\n{funcs}\n\n"
        f"Strings:\n{strs}\n\n"
        f"Imports:\n{imps}\n\n"
        "Proceed with your analysis using the tools."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": init_info},
    ]

    log_entries = []

    while True:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        msg = response.choices[0].message
        messages.append(msg)

        if msg.content:
            log_entries.append(f"ASSISTANT: {msg.content}")
        if msg.tool_calls:
            for tc in msg.tool_calls:
                log_entries.append(f"ACTION: {tc.function.name}({tc.function.arguments})")

        # 检查是否得到了最终答案
        if msg.content:
            content = msg.content.strip()
            if content.startswith("{") and content.endswith("}"):
                try:
                    vuln = json.loads(content)
                    if all(k in vuln for k in ("vuln_type","location","cause")):
                        with open("output/vuln.json", "w") as f:
                            json.dump(vuln, f, indent=2)
                        log_entries.append("Final answer saved to output/vuln.json")
                        break
                except:
                    pass

        if not msg.tool_calls and msg.content:
            # 纯文本但非 JSON，可能还是 final？不做强制停止，继续循环
            pass

        # 处理工具调用
        if msg.tool_calls:
            for tool_call in msg.tool_calls:
                obs = process_tool_call(tool_call)
                log_entries.append(f"OBSERVATION: {obs[:800]}{'...' if len(obs)>800 else ''}")
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": obs
                })

        # 安全限制
        if len(messages) > 50:
            print("Too many turns, stopping.")
            break

    with open("logs/run.txt", "w") as logf:
        logf.write("\n\n".join(log_entries))

if __name__ == "__main__":
    main()
