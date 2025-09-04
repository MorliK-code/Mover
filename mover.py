import os 
import time
import shutil
import configparser
import re
import asyncio
import subprocess
import datetime
from colorama import Fore, Style, init
import psutil
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import threading, queue
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.shortcuts import print_formatted_text
import sys

init(autoreset=True, convert=True, wrap=True)

last_launch_time = time.time()
active_converters = {}
last_skip_report = {}
active_senders = {}
print_lock = threading.Lock()
input_buffer = []
cmd_queue = queue.Queue()

config_state = {
    "settings": {},
    "main_paths": [],
    "ip_destinations": {},
    "ip_switch": {}
}


def log(msg, level="info"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prefix = f"[{now}]"

    color = Fore.WHITE
    if level == "success":
        color = Fore.GREEN
    elif level == "warning":
        color = Fore.YELLOW
    elif level == "error":
        color = Fore.RED

    print_formatted_text(ANSI(f"{color}{prefix} {msg}{Style.RESET_ALL}"))


def suppress_traceback(exctype, value, tb):
    if exctype in (KeyboardInterrupt, SystemExit):
        print("Скрипт завершён.", flush=True)

sys.excepthook = suppress_traceback


def is_vpn_connected(vpn_name, vpn_user=None, vpn_pass=None):
    try:
        result = subprocess.run("rasdial", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return vpn_name.lower() in result.stdout.lower()
    except Exception as e:
        log(f"Ошибка проверки VPN: {e}", level="error")
        return False


def restart_vpn(vpn_name, vpn_user=None, vpn_pass=None):
    log("Перезапуск VPN...", level="warning")
    try:
        subprocess.run(f"rasdial {vpn_name} /disconnect", shell=True)
        time.sleep(10)
        subprocess.run(f'rasdial {vpn_name} {vpn_user} {vpn_pass}', shell=True)
        log("VPN перезапущен", level="success")
    except Exception as e:
        log(f"Ошибка перезапуска VPN: {e}", level="error")


async def vpn_monitor_loop():
    while True:
        settings = config_state["settings"]
        vpn_name = settings.get("vpn_name", "")
        vpn_user = settings.get("vpn_user", "")
        vpn_pass = settings.get("vpn_pass", "")
        vpn_check_interval_sec = settings.get("vpn_check_interval_sec", 60)

        if vpn_name and not is_vpn_connected(vpn_name, vpn_user, vpn_pass):
            log("VPN не подключён — выполняю перезапуск", level="error")
            restart_vpn(vpn_name, vpn_user, vpn_pass)

        await asyncio.sleep(vpn_check_interval_sec)


def load_config(config_path="config.ini"):
    config = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    config.optionxform = str
    config.read(config_path, encoding="utf-8")

    settings = {
        "interval": int(config["settings"].get("check_interval_sec", 5)),
        "stable_time": int(config["settings"].get("min_stable_time_sec", 3)),
        "converter_idle_minutes": int(config["settings"].get("converter_idle_minutes", 30)),
        "converter_folder_name": config["settings"].get("converter_folder_name", "converter"),
        "converter_start_interval_min": int(config["settings"].get("converter_start_interval_min", 5)),
        "sender_folder_name": config["settings"].get("sender_folder_name", "BatToServer"),
        "vpn_name": config["settings"].get("vpn_name", ""),
        "vpn_user": config["settings"].get("vpn_user", ""),
        "vpn_pass": config["settings"].get("vpn_pass", ""),
        "vpn_check_interval_sec": int(config["settings"].get("vpn_check_interval_sec", 60)),
        "cpu_workers": max(1, int(config["settings"].get("cpu_workers", 1))),
        "check_settings_interval_min": int(config["settings"].get("check_settings_interval_min", 5)),
    }

    main_paths = list(config["main"].values())
    ip_destinations = dict(config["ips"])
    ip_switch = {ip: config["switch"].get(ip, "false").lower() == "true" for ip in ip_destinations}

    return settings, main_paths, ip_destinations, ip_switch


def update_config_state():
    settings, main_paths, ip_destinations, ip_switch = load_config()
    config_state["settings"] = settings
    config_state["main_paths"] = main_paths
    config_state["ip_destinations"] = ip_destinations
    config_state["ip_switch"] = ip_switch


async def checksettings():
    while True:
        try:
            update_config_state()
            interval_min = config_state["settings"].get("check_settings_interval_min", 5)
            log("Настройки перезагружены", level="info")
        except Exception as e:
            log(f"Ошибка перезагрузки настроек: {e}", level="error")

        
        await asyncio.sleep(interval_min * 60)


def is_file_stable(path, min_stable_time):
    try:
        last_mod = os.path.getmtime(path)
        return (time.time() - last_mod) > min_stable_time
    except Exception as e:
        log(f"Ошибка проверки стабильности файла {path}: {e}", level="error")
        return False


def process_ip_folder(args):
    date_folder_path, ip_folder, ip, dest_base, min_stable_time = args
    moved = 0
    messages = []
    exclude_pattern = re.compile(r"^index\d+(\.bin)?$", re.IGNORECASE)
    src_ip_path = os.path.join(date_folder_path, ip_folder)
    if not os.path.isdir(src_ip_path):
        return 0, messages
    try:
        filenames = os.listdir(src_ip_path)
    except Exception as e:
        messages.append(f"Ошибка чтения {src_ip_path}: {e}")
        return 0, messages
    for filename in filenames:
        if exclude_pattern.match(filename):
            continue
        file_path = os.path.join(src_ip_path, filename)
        if not os.path.isfile(file_path) or not is_file_stable(file_path, min_stable_time):
            continue
        dst_dir = os.path.join(dest_base, os.path.basename(date_folder_path), ip_folder)
        os.makedirs(dst_dir, exist_ok=True)
        dst_file_path = os.path.join(dst_dir, filename)
        try:
            if os.path.exists(dst_file_path):
                os.remove(dst_file_path)
            shutil.move(file_path, dst_file_path)
            moved += 1
            messages.append(f"Перемещён файл: {file_path} → {dst_file_path}")
        except Exception as e:
            messages.append(f"Ошибка при перемещении {file_path}: {e}")
    return moved, messages


def process_path(base_path, ip, dest, min_stable_time):
    total_moved = 0
    all_messages = []
    if not os.path.isdir(base_path):
        return 0, all_messages
    try:
        date_folders = os.listdir(base_path)
    except Exception as e:
        all_messages.append(f"Ошибка чтения папок {base_path}: {e}")
        return 0, all_messages
    tasks = []
    for date_folder in date_folders:
        date_folder_path = os.path.join(base_path, date_folder)
        if not os.path.isdir(date_folder_path):
            continue
        try:
            ip_folders = os.listdir(date_folder_path)
        except Exception as e:
            all_messages.append(f"Ошибка чтения папок {date_folder_path}: {e}")
            continue
        for ip_folder in ip_folders:
            if not ip_folder.startswith(ip):
                continue
            tasks.append((date_folder_path, ip_folder, ip, dest, min_stable_time))
    # Многопроцессный запуск для каждой папки
    moved_results = []
    with ProcessPoolExecutor() as executor:
        moved_results = list(executor.map(process_ip_folder, tasks))
    for moved, messages in moved_results:
        total_moved += moved
        all_messages.extend(messages)
    return total_moved, all_messages


def last_modification_time(path):
    latest = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                mtime = os.path.getmtime(os.path.join(root, f))
                if mtime > latest:
                    latest = mtime
            except Exception:
                continue
    return latest


def is_converter_process_running(bat_path):
    bat_path_norm = os.path.normcase(os.path.abspath(bat_path))
    for proc in psutil.process_iter(['name','cmdline']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in ('cmd.exe','powershell.exe'):
                cmdline = proc.info['cmdline']
                if cmdline and any(bat_path_norm == os.path.normcase(os.path.abspath(arg)) for arg in cmdline):
                    return True
        except Exception:
            continue
    return False


def run_bat_process(bat_path):
    working_dir = os.path.dirname(bat_path)
    try:
        subprocess.run(f'cmd /c call "{bat_path}"', cwd=working_dir)
        return f"Выполнен: {bat_path}"
    except Exception as e:
        return f"Ошибка: {bat_path}, {e}"


def is_sender_running(bat_path):
    bat_path_norm = os.path.normcase(os.path.abspath(bat_path))
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in ('cmd.exe', 'powershell.exe'):
                cmdline = proc.info['cmdline']
                if cmdline and any(bat_path_norm == os.path.normcase(os.path.abspath(arg)) for arg in cmdline):
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def run_sender(disk, sender_folder_name):
    bat_path = os.path.join(f"{disk}\\", sender_folder_name, "videoToServer.bat")
    if not os.path.exists(bat_path):
        log(f"Bat файл не найден: {bat_path}", level="error")
        return

    if active_senders.get(disk, False):
        log(f"Отправщик для {disk} уже запущен", level="warning")
        return

    active_senders[disk] = True
    try:
        subprocess.Popen(
            f'start "" /D "{os.path.dirname(bat_path)}" cmd /c call "{bat_path}"',
            shell=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        log(f"Запуск отправщика для {disk}", level="success")
    except Exception as e:
        log(f"Ошибка запуска отправщика {disk}: {e}", level="error")
    finally:
        active_senders[disk] = False

active_senders = {}


async def launch_idle_converters(ip_destinations, idle_minutes, converter_folder_name, min_start_interval_sec, executor):
    global last_launch_time, last_skip_report
    now = time.time()

    if now - last_launch_time < min_start_interval_sec:
        return

    to_start = {}
    for ip, dest_path in ip_destinations.items():
        disk_letter = os.path.splitdrive(dest_path)[0].upper()
        if not disk_letter:
            continue
        backup_path = os.path.join(disk_letter + os.sep, "backupfile")
        converter_bat = os.path.join(disk_letter + os.sep, converter_folder_name, "start.bat")

        if not os.path.isdir(backup_path) or not os.path.exists(converter_bat):
            continue

        if is_converter_process_running(converter_bat):
            active_converters[disk_letter] = {"bat_path": converter_bat, "last_check": now}
            continue

        last_mod = last_modification_time(backup_path)
        if last_mod == 0 or (now - last_mod) >= idle_minutes * 60:
            to_start[disk_letter] = converter_bat
        else:
            if last_skip_report.get(disk_letter, 0) < last_launch_time:
                log(f"На диске {disk_letter} были изменения менее {idle_minutes} минут назад — запуск конвертера пропущен", level="warning")
                last_skip_report[disk_letter] = now

    if not to_start:
        last_launch_time = now
        return

    log(f"Запускаем конвертеры на дисках: {', '.join(to_start.keys())}", level="success")

    futures = []
    for disk, bat_path in to_start.items():
        futures.append(executor.submit(run_bat_process, bat_path))
        active_converters[disk] = {"bat_path": bat_path, "last_check": now}

    # Ждём завершения всех запущенных конвертеров в пуле, не блокируя главный цикл asyncio
    for future in futures:
        asyncio.get_running_loop().run_in_executor(None, future.result)

    last_launch_time = now


def run_sender_for_disk(disk, sender_folder_name):
    if active_converters.get(disk, False):
        log(f"Пропуск отправки для {disk} конвертер ещё работает", "warning")
        return

    if active_senders.get(disk, False):
        log(f"Пропуск отправки для {disk}: сендер уже запущен", "warning")
        return

    active_senders[disk] = True
    try:
        run_sender(disk, sender_folder_name)
    finally:
        active_senders[disk] = False


async def monitor_converter_completion(check_interval_sec, sender_folder_name):
    while True:
        to_remove = []
        for disk, info in list(active_converters.items()):
            bat_path = info["bat_path"]
            if not is_converter_process_running(bat_path):
                log(f"Конвертер на диске {disk} завершил работу", level="success")
                active_converters[disk] = False
                run_sender_for_disk(disk, sender_folder_name)
                to_remove.append(disk)
        for disk in to_remove:
            active_converters.pop(disk, None)
        await asyncio.sleep(check_interval_sec)


async def monitor_converters(ip_destinations, idle_minutes, converter_folder_name, check_interval_sec, min_start_interval_sec):
    await asyncio.sleep(min_start_interval_sec)
    while True:
        await launch_idle_converters(ip_destinations, idle_minutes, converter_folder_name, min_start_interval_sec)
        await asyncio.sleep(check_interval_sec)


def process_path_star(args):
    return process_path(*args)


async def main_loop(executor):
    total_moved = 0
    loop = asyncio.get_running_loop()

    while True:
        moved_this_cycle = 0
        all_messages = []
        tasks_list = []

        settings = config_state["settings"]
        stable_time = settings.get("stable_time", 3)
        interval = settings.get("interval", 5)

        ip_destinations = config_state["ip_destinations"]
        ip_switch = config_state["ip_switch"]
        main_paths = config_state["main_paths"]

        for ip, enabled in ip_switch.items():
            if not enabled:
                continue
            dest = ip_destinations.get(ip)
            if not dest:
                continue
            for base_path in main_paths:
                tasks_list.append((base_path, ip, dest, stable_time))

        if tasks_list:
            try:
                futures = [loop.run_in_executor(executor, process_path_star, task) for task in tasks_list]
                results = await asyncio.gather(*futures)

                for moved, messages in results:
                    moved_this_cycle += moved
                    all_messages.extend(messages)
                    for msg in messages:
                        log(msg, level="info")
            except Exception as e:
                log(f"Ошибка пула процессов: {e}", level="error")

        total_moved += moved_this_cycle
        log(f"Цикл завершён. Перемещено файлов: {moved_this_cycle}, всего: {total_moved}", level="success")
        await asyncio.sleep(interval)


async def command_loop():
    log("Командный режим включён. Введите 'help'", level="info")
    session = PromptSession()

    with patch_stdout():
        while True:
            try:
                cmd = await session.prompt_async(">> ")
                cmd = cmd.strip().lower()

                if cmd == "help":
                    print("""Доступные команды:

help                - показать доступные команды
reload              - перезагрузить config.ini
start convert       - принудительно запустить конверторы на всех дисках
restart vpn         - принудительно перезапустить VPN
status              - показать активные процессы/отправщики
exit                - завершить скрипт
""")
                    
                elif cmd == "reload":
                    update_config_state()
                    log("Настройки перезагружены вручную", level="success")
                
                elif cmd == "start convert":
                    settings = config_state["settings"]
                    await launch_idle_converters(
                        config_state["ip_destinations"],
                        settings["converter_idle_minutes"],
                        settings["converter_folder_name"],
                        0
                    )
                    log("Запуск конвертеров и отправщиков выполнен вручную", level="success")

                elif cmd == "restart vpn":
                    settings = config_state["settings"]
                    vpn_name = settings.get("vpn_name", "")
                    vpn_user = settings.get("vpn_user", "")
                    vpn_pass = settings.get("vpn_pass", "")
                    restart_vpn(vpn_name, vpn_user, vpn_pass)
                    log("Перезапуск VPN выполнен вручную", level="success")

                elif cmd == "status":
                    conv_running = []
                    for d, info in active_converters.items():
                        if info and is_converter_process_running(info["bat_path"]):
                            conv_running.append(d)

                    send_running = []
                    for d in active_senders.keys():
                        bat_path = os.path.join(
                            f"{d}\\",
                            config_state["settings"]["sender_folder_name"],
                            "videoToServer.bat"
                        )
                        if is_sender_running(bat_path):
                            send_running.append(d)

                    log(f"Активные конвертеры: {conv_running}", level="info")
                    log(f"Активные отправщики: {send_running}", level="info")


                elif cmd == "exit":
                    log("Выход из программы...", level="warning")
                    os._exit(0)

                elif cmd:
                    log(f"Неизвестная команда: {cmd}", level="error")

            except KeyboardInterrupt:
                print()  # Ctrl+C очищает строку ввода
                continue
            except Exception as e:
                log(f"Ошибка в командном режиме: {e}", level="error")



async def main_async(tasks):
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass


def main():
    update_config_state()
    settings = config_state["settings"]

    cpu_workers = settings.get("cpu_workers", 1)  # берём из конфига
    log(f"Используется CPU воркеров: {cpu_workers}", level="success")

    executor = ProcessPoolExecutor(max_workers=cpu_workers)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    tasks = [
        loop.create_task(command_loop()),
        loop.create_task(main_loop(executor)),
        loop.create_task(monitor_converters(
            config_state["ip_destinations"],
            settings["converter_idle_minutes"],
            settings["converter_folder_name"],
            settings["interval"],
            settings["converter_start_interval_min"] * 60
        )),
        loop.create_task(monitor_converter_completion(settings["interval"], settings["sender_folder_name"])),
        loop.create_task(vpn_monitor_loop()),
        loop.create_task(checksettings()),
    ]

    try:
        loop.run_until_complete(main_async(tasks))
    except (KeyboardInterrupt, SystemExit):
        log("Остановлено пользователем.", level="warning")
        for task in tasks:
            task.cancel()
        try:
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        except Exception:
            pass
    finally:
        executor.shutdown(wait=True)
        try:
            loop.stop()
            loop.close()
        except Exception:
            pass


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()