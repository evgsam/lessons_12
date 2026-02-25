import csv
import os

from volatility3.framework import contexts, automagic, plugins
from volatility3.plugins.windows import pslist, netscan

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
        open_method=None,  # для вашей версии Vol3 параметр file_consumer отсутствует
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


def main():
    if not os.path.exists(MEMORY_PATH):
        raise FileNotFoundError(f"Не найден дамп: {MEMORY_PATH}")

    ctx, automagics_list, base_config_path = init_framework()

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
