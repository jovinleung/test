import os
import re

WORKFLOW_FILE = ".github/workflows/custom.yml"
TEMPLATE_DIR = "trunk/configs/templates"

# 获取设备名列表
devices = sorted([
    f.replace(".config", "") for f in os.listdir(TEMPLATE_DIR)
    if f.endswith(".config")
])

if not devices:
    print("❌ No device config files found.")
    exit(1)

# 构造 YAML options 列表
device_list_yaml = "\n            - " + "\n            - ".join(devices)

# 替换 build.yml 中的 target options
with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
    content = f.read()

new_content = re.sub(
    r"(target:\s*\n\s*description:.*?\n\s*required: true\n\s*options:)([\s\S]*?)(\n\s*\w+:|$)",
    r"\1" + device_list_yaml + r"\3",
    content,
    flags=re.MULTILINE,
)

# 保存修改
with open(WORKFLOW_FILE, "w", encoding="utf-8") as f:
    f.write(new_content)

print(f"✅ Updated target list: {devices}")
