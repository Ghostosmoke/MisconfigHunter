"""
🔐 Security Auditor — Единый пакет проверок безопасности
CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD
"""

from core import (
    Severity,
    SecurityReport,
    BaseCheck,
    CheckRegistry
)

# Импортируем все проверки для регистрации
from Easy_Check import *
from Medium_Check import *
from Hard_Check import *

# Публичный API
__all__ = [
    'Severity',
    'SecurityReport',
    'BaseCheck',
    'CheckRegistry',
    'run_check',
    'run_all_checks',
    'get_check',
    'get_all_checks',
    'print_summary'
]

__version__ = "2.0.0"


def get_check(name: str):
    """Получить проверку по имени или ID."""
    return CheckRegistry.get_check(name)


def get_all_checks():
    """Получить все зарегистрированные проверки."""
    return CheckRegistry.get_all_checks()


def run_check(name: str, verbose: bool = True):
    """Запустить одну проверку."""
    check_class = get_check(name)
    if not check_class:
        print(f"❌ Проверка '{name}' не найдена!")
        return None
    try:
        check_instance = check_class()
        report = check_instance.check()
        if verbose:
            report.print_report()
        return report
    except Exception as e:
        print(f"⚠️  Ошибка при выполнении {name}: {e}")
        return None


def run_all_checks(level: str = None, verbose: bool = True):
    """Запустить набор проверок."""
    return CheckRegistry.run_all(level=level, verbose=verbose)


def print_summary(reports):
    """Вывести сводную статистику."""
    CheckRegistry.print_summary(reports)


# Удобный запуск из CLI
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            print("📋 Доступные проверки:")
            for name, check in get_all_checks().items():
                severity = getattr(check, 'SEVERITY', Severity.INFO)
                print(f"  {check.CHECK_ID:40} [{severity.value}]")
        elif sys.argv[1] == "--level":
            level = sys.argv[2] if len(sys.argv) > 2 else "easy"
            reports = run_all_checks(level=level)
            print_summary(reports)
        else:
            report = run_check(sys.argv[1])
    else:
        reports = run_all_checks()
        print_summary(reports)