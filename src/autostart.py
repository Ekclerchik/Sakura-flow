"""Task Scheduler autostart functions."""
import sys
import logging
from datetime import datetime
from pathlib import Path
import pythoncom
import win32com.client

# Handle both relative and absolute imports
try:
    from .config import TASK_NAME
except ImportError:
    from src.config import TASK_NAME

# С Utils: Task Scheduler передаёт этот аргумент при логоне. По нему приложение
# понимает, что запущено автозапуском, и обязано поднять стратегию даже если
# last_bat в state ещё пустой (первый логон после установки).
AUTOSTART_ARG = "--sakura-autostart"


def _com_init():
    """win32com требует CoInitialize в КАЖДОМ потоке, включая фоновые."""
    try:
        pythoncom.CoInitialize()
        return True
    except Exception:
        return False


def _com_done(initialized):
    if initialized:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass


def enable_autostart():
    """Enable autostart via Task Scheduler."""
    initialized = _com_init()
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')

        # Создаём задачу
        task_def = scheduler.NewTask(0)
        task_def.RegistrationInfo.Description = 'Autostart SakuraFlow'
        task_def.RegistrationInfo.Author = 'Ekcler'

        # Настраиваем триггер на запуск при входе в систему
        trigger = task_def.Triggers.Create(9)  # 9 = TASK_TRIGGER_LOGON
        trigger.Id = 'LogonTrigger'
        trigger.StartBoundary = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        # Настраиваем действие для запуска SakuraFlow.exe
        action = task_def.Actions.Create(0)  # 0 = TASK_ACTION_EXEC
        action.ID = 'SakuraFlowStart'
        action.Path = str(Path(sys.executable).resolve())
        action.Arguments = AUTOSTART_ARG

        # Настраиваем параметры задачи
        task_def.Settings.Enabled = True
        task_def.Settings.Hidden = False
        task_def.Settings.RunOnlyIfIdle = False
        task_def.Settings.DisallowStartIfOnBatteries = False
        task_def.Settings.StopIfGoingOnBatteries = False
        task_def.Settings.ExecutionTimeLimit = 'PT0S'  # Без ограничения времени
        task_def.Principal.RunLevel = 1  # 1 = TASK_RUNLEVEL_HIGHEST (запуск с правами администратора)
        task_def.Principal.LogonType = 3  # 3 = TASK_LOGON_INTERACTIVE_TOKEN

        # Регистрируем задачу
        root_folder.RegisterTaskDefinition(
            TASK_NAME,
            task_def,
            6,  # TASK_CREATE_OR_UPDATE
            None,  # Пользователь (None = текущий пользователь)
            None,  # Пароль
            3   # TASK_LOGON_INTERACTIVE_TOKEN
        )
        logging.info(f"Автозапуск включён через Планировщик задач: {TASK_NAME}")
    except Exception as e:
        logging.error(f"Ошибка при включении автозапуска: {e}")
    finally:
        _com_done(initialized)


def disable_autostart():
    """Disable autostart via Task Scheduler."""
    initialized = _com_init()
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')
        root_folder.DeleteTask(TASK_NAME, 0)
        logging.info("Автозапуск отключён через Планировщик задач")
    except Exception as e:
        logging.error(f"Ошибка при отключении автозапуска: {e}")
    finally:
        _com_done(initialized)


def is_autostart_enabled():
    """Check if autostart is enabled."""
    initialized = _com_init()
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')
        root_folder.GetTask(TASK_NAME)
        return True
    except Exception:
        return False
    finally:
        _com_done(initialized)


def fix_autostart_path():
    """Fix autostart task path/arguments if exe was moved or reinstalled."""
    if not is_autostart_enabled():
        return
    initialized = _com_init()
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')
        task = root_folder.GetTask(TASK_NAME)
        action = task.Definition.Actions[0]
        current_path = action.Path
        current_args = getattr(action, 'Arguments', '') or ''
        if not Path(current_path).exists() or AUTOSTART_ARG not in current_args:
            logging.info(
                f"Путь/аргументы автозапуска устарели: {current_path} {current_args!r}, обновляю..."
            )
            enable_autostart()
    except Exception as e:
        logging.error(f"Ошибка проверки пути автозапуска: {e}")
    finally:
        _com_done(initialized)
