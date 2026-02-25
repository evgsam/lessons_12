import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# Добавляем путь к Volatility 3 в системный путь
# Убедитесь, что папка volatility3 находится в той же директории, что и скрипт
VOLATILITY_PATH = os.path.abspath('/home/user/python_projects/lessons_12/.venv/bin')
if os.path.exists(VOLATILITY_PATH):
    sys.path.append(VOLATILITY_PATH)
else:
    print("[!] Папка volatility3 не найдена. Укажите правильный путь.")
    print("[!] Скачайте её: git clone https://github.com/volatilityfoundation/volatility3.git")
    sys.exit(1)

# Импортируем необходимые модули из Volatility 3
try:
    from volatility3.cli import Volatility
    from volatility3.framework import contexts
    from volatility3.framework.automagic import symbol_cache, mac, linux, windows
    from volatility3.framework.configuration import requirements
    from volatility3.framework.layers import resources
    from volatility3.framework.renderers import conversion
    from volatility3.plugins.windows import pslist, netscan
except ImportError as e:
    print(f"[!] Ошибка импорта Volatility: {e}")
    print("[!] Убедитесь, что путь к volatility3 указан верно.")
    sys.exit(1)

# --- Конфигурация ---
DUMP_FILE = "memory_dumps/var-2.vmem"  # Укажите путь к вашему дампу
OUTPUT_DIR = "output"

# Создаем папку для результатов
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_volatility_plugin(plugin_class, dump_file, ctx):
    """
    Универсальная функция для запуска плагинов Volatility 3.
    """
    print(f"[*] Запуск плагина: {plugin_class.__name__}")
    try:
        # Создаем базовую конфигурацию для плагина
        base_config_path = f"plugins.{plugin_class.__name__}"
        ctx.config[requirements.TranslationLayerRequirement.get_conf_name("nt")] = "nt"
        ctx.config[requirements.SymbolTableRequirement.get_conf_name("nt")] = "nt"
        ctx.config[base_config_path] = True

        # Добавляем требование к файлу
        ctx.config["single_location"] = dump_file

        # Запускаем плагин
        plugin = plugin_class(ctx, base_config_path)
        result = plugin.run()

        # Парсим результат в pandas DataFrame
        rows = []
        for level, item in result:
            if isinstance(item, dict):
                # Плагины pslist и netscan возвращают список словарей
                rows.append(item)
            elif isinstance(item, list):
                # Альтернативный формат
                rows.extend(item)

        df = pd.DataFrame(rows)
        print(f"[+] Плагин {plugin_class.__name__} выполнен. Получено записей: {len(df)}")
        return df
    except Exception as e:
        print(f"[-] Ошибка при выполнении плагина {plugin_class.__name__}: {e}")
        return pd.DataFrame()  # Возвращаем пустой DataFrame в случае ошибки

def main():
    print("[=======================================]")
    print("[=  Memory Dump Forensic Analyzer      =]")
    print("[=======================================]")

    # Проверка существования файла дампа
    if not os.path.exists(DUMP_FILE):
        print(f"[!] Файл дампа не найден: {DUMP_FILE}")
        print(f"[!] Пожалуйста, поместите ваш дамп в папку 'memory_dumps/'.")
        return

    # Создаем контекст Volatility
    ctx = contexts.Context()

    # --- Этап 1: Информация о системе (опционально) ---
    print("\n[1] Получение информации о системе...")
    # В Volatility 3 плагин 'info' находится в windows.info
    from volatility3.plugins.windows import info as win_info
    sys_info_df = run_volatility_plugin(win_info.Info, DUMP_FILE, ctx)
    if not sys_info_df.empty:
        print("\n[ Системная информация ]")
        print(sys_info_df.head(10))  # Выводим основные параметры

    # --- Этап 2: Извлечение ключевых артефактов ---
    print("\n[2] Извлечение ключевых артефактов...")

    # 2.1 Список процессов (pslist)
    pslist_df = run_volatility_plugin(pslist.PsList, DUMP_FILE, ctx)
    if not pslist_df.empty:
        # Сохраняем в CSV
        csv_path = os.path.join(OUTPUT_DIR, "pslist.csv")
        pslist_df.to_csv(csv_path, index=False)
        print(f"[+] Список процессов сохранен: {csv_path}")
        # Выводим первые несколько процессов для наглядности
        print("\n[ Список процессов (первые 5) ]")
        print(pslist_df[['PID', 'PPID', 'ImageFileName', 'CreateTime']].head(5))

    # 2.2 Сетевые соединения (netscan) для Windows >= Vista
    netscan_df = run_volatility_plugin(netscan.NetScan, DUMP_FILE, ctx)
    if not netscan_df.empty:
        csv_path = os.path.join(OUTPUT_DIR, "netscan.csv")
        netscan_df.to_csv(csv_path, index=False)
        print(f"[+] Сетевые соединения сохранены: {csv_path}")

        # Фильтруем только установленные соединения (Established) и не-local адреса
        if 'State' in netscan_df.columns and 'RemoteAddr' in netscan_df.columns:
            established = netscan_df[netscan_df['State'] == 'ESTABLISHED']
            # Простой фильтр для исключения локальных адресов (можно улучшить)
            suspicious = established[~established['RemoteAddr'].str.startswith(('127.', '::1'), na=False)]
            print("\n[ Подозрительные соединения (ESTABLISHED) ]")
            print(suspicious[['PID', 'LocalAddr', 'RemoteAddr', 'State']].head(10))

    # --- Этап 3: Визуализация результатов ---
    print("\n[3] Создание визуализации...")
    if not pslist_df.empty:
        plt.figure(figsize=(12, 6))

        # Пытаемся извлечь время создания и подсчитать процессы по минутам
        if 'CreateTime' in pslist_df.columns:
            # Преобразуем время создания в datetime (формат Volatility: 2024-01-01 12:34:56.000000)
            pslist_df['CreateTime'] = pd.to_datetime(pslist_df['CreateTime'], errors='coerce')
            # Удаляем строки с некорректным временем
            pslist_df = pslist_df.dropna(subset=['CreateTime'])

            if not pslist_df.empty:
                # Группируем по минутам создания
                pslist_df['TimeBin'] = pslist_df['CreateTime'].dt.floor('1min')
                proc_over_time = pslist_df.groupby('TimeBin').size().reset_index(name='Count')

                # Строим график
                sns.lineplot(data=proc_over_time, x='TimeBin', y='Count', marker='o')
                plt.title('Количество запущенных процессов по времени')
                plt.xlabel('Время')
                plt.ylabel('Количество процессов')
                plt.xticks(rotation=45)
                plt.tight_layout()

                # Сохраняем график
                plot_path = os.path.join(OUTPUT_DIR, "processes_summary.png")
                plt.savefig(plot_path, dpi=150)
                print(f"[+] Визуализация сохранена: {plot_path}")
                plt.close()
            else:
                print("[-] Нет данных о времени создания для визуализации.")
        else:
            print("[-] Колонка 'CreateTime' не найдена. Пропускаем визуализацию.")
    else:
        print("[-] Нет данных о процессах для визуализации.")

    print("\n[=======================================]")
    print("[=  Анализ завершен!                   =]")
    print("[=======================================]")

if __name__ == "__main__":
    main()