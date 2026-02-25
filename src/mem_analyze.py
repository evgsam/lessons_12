import csv
import os

from volatility3.framework import contexts, automagic, plugins
from volatility3.plugins.windows import pslist, netscan, info

MEMORY_PATH = os.path.expanduser(
    "~/python_projects/lessons_12/memory_dumps/var-2.vmem"
)
OUTPUT_PROCESSES = "processes.csv"
OUTPUT_CONNECTIONS = "connections.csv"


def init_framework():
    ctx = contexts.Context()
    automagics_list = automagic.available(ctx)

    # КЛЮЧЕВАЯ СТРОКА: сюда LayerStacker смотрит за single_location
    single_location = f"file:{MEMORY_PATH}"
    ctx.config["automagic.LayerStacker.single_location"] = single_location

    # базовый префикс для плагинов (можно оставить как есть)
    base_config_path = "plugins"

    return ctx, automagics_list, base_config_path


def run_plugin(ctx, automagics_list, base_config_path, plugin_cls):
    constructed = plugins.construct_plugin(
        ctx,
        automagics_list,
        plugin_cls,
        base_config_path,
        progress_callback=None,
        open_method=None,
    )
    return constructed.run()


def treegrid_to_csv(treegrid, filename: str):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = None

        def visitor(node, _acc):
            nonlocal writer
            if writer is None:
                headers = [col.name for col in treegrid.columns]
                writer = csv.writer(f)
                writer.writerow(headers)
            row = [repr(node.values[i]) for i in range(len(treegrid.columns))]
            writer.writerow(row)
            return None

        treegrid.populate(visitor, None)

def collect_info_rows(treegrid):
    rows = []

    def visitor(node, _acc):
        # node.values = что-то вроде ['NtMajorVersion', '6']
        if len(node.values) >= 2:
            rows.append((str(node.values[0]), str(node.values[1])))
        return None

    treegrid.populate(visitor, None)
    return rows


def pretty_print_os(info_rows):
    data = {k: v for k, v in info_rows}

    major = data.get("NtMajorVersion")
    minor = data.get("NtMinorVersion")
    is64 = data.get("Is64Bit") == "True"
    build = data.get("NTBuildLab", "")
    system_time = data.get("SystemTime", "")

    # Определяем название ОС по версии NT
    if major == "6" and minor == "1":
        os_name = "Windows 7"
    elif major == "6" and minor == "0":
        os_name = "Windows Vista"
    elif major == "6" and minor == "2":
        os_name = "Windows 8"
    elif major == "6" and minor == "3":
        os_name = "Windows 8.1"
    elif major == "10" and minor == "0":
        os_name = "Windows 10/11"
    else:
        os_name = f"Windows (NT {major}.{minor})"

    arch = "x64" if is64 else "x86"

    print("=== Информация об ОС дампа ===")
    print(f"ОС: {os_name} {arch}")
    if build:
        print(f"Сборка: {build}")
    if system_time:
        print(f"Время снимка памяти: {system_time}")


def main():
    if not os.path.exists(MEMORY_PATH):
        raise FileNotFoundError(f"Не найден дамп: {MEMORY_PATH}")

    ctx, automagics_list, base_config_path = init_framework()

    info_grid = run_plugin(ctx, automagics_list, base_config_path, info.Info)
    info_rows = collect_info_rows(info_grid)
    pretty_print_os(info_rows)

    # Список процессов
    pslist_grid = run_plugin(ctx, automagics_list, base_config_path, pslist.PsList)
    treegrid_to_csv(pslist_grid, OUTPUT_PROCESSES)
    print(f"[+] Сохранены процессы в {OUTPUT_PROCESSES}")

    # Сетевые соединения (если поддерживается дампом)
    netscan_grid = run_plugin(ctx, automagics_list, base_config_path, netscan.NetScan)
    treegrid_to_csv(netscan_grid, OUTPUT_CONNECTIONS)
    print(f"[+] Сохранены соединения в {OUTPUT_CONNECTIONS}")


if __name__ == "__main__":
    main()
