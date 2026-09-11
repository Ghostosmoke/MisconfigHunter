"""
main.py — точка входа в MisconfigHunter.

Примечание для тех, кто сверяется с этим файлом:
в find_file.py НЕТ функции start_search(target_path, mode) — есть
audit_project(path, levels), которая принимает список уровней проверки
('easy', 'medium', 'hard') и возвращает объект AuditReport. Этот main.py
подключает флаги --easy/--deep именно к audit_project(), а не к
гипотетической start_search() — такой функции в проекте не существует.

Уровни проекта — easy / medium / hard. Здесь они упрощены до двух
пользовательских режимов:
    --easy  → только 'easy'                  (быстрая поверхностная проверка)
    --deep  → 'easy' + 'medium' + 'hard'      (глубокая, тщательная проверка)
"""

import sys
import argparse
from pathlib import Path

# --- Настройка путей ---------------------------------------------------
# Модули проекта (Easy_Check.py, Medium_Check.py, Hard_Check.py, find_file.py)
# лежат в папке Check_all/ рядом с этим файлом. Модули внутри Check_all
# импортируют друг друга по плоским именам (from Easy_Check import ...),
# поэтому саму папку Check_all нужно добавить в sys.path перед импортом.
CHECK_ALL_DIR = Path(__file__).resolve().parent / "Check_all"

if not CHECK_ALL_DIR.is_dir():
    raise RuntimeError(
        f"Не найдена папка Check_all/ рядом с main.py (ожидалась здесь: {CHECK_ALL_DIR})."
    )

if str(CHECK_ALL_DIR) not in sys.path:
    sys.path.insert(0, str(CHECK_ALL_DIR))

from Check_all.find_file import audit_project  # noqa: E402 (импорт после правки sys.path — намеренно)


def build_parser() -> argparse.ArgumentParser:
    """Собирает парсер аргументов командной строки."""
    parser = argparse.ArgumentParser(
        prog="MisconfigHunter",
        description="Статический аудитор безопасности инфраструктурного кода "
                     "(Kubernetes, Docker, Terraform, CloudFormation, CI/CD).",
    )

    # --easy и --deep взаимоисключающие: нельзя запустить и быструю,
    # и глубокую проверку одновременно.
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "-e", "--easy",
        action="store_true",
        help="Быстрая поверхностная проверка — только самые очевидные проблемы.",
    )
    mode_group.add_argument(
        "-d", "--deep",
        action="store_true",
        help="Глубокая проверка — включает все уровни анализа, в т.ч. кросс-файловый.",
    )

    parser.add_argument(
        "-t", "--target",
        default=".",
        help="Папка (или файл) для проверки. По умолчанию — текущая папка.",
    )

    return parser


def main() -> None:
    """Точка входа программы."""
    args = build_parser().parse_args()

    # Если пользователь не указал ни --easy, ни --deep — по умолчанию
    # запускаем быструю проверку, а не всё подряд: это ожидаемо более
    # быстрый и менее шумный вариант "по умолчанию".
    if args.deep:
        levels = ["easy", "medium", "hard"]
        mode_description = "ГЛУБОКУЮ (все уровни: easy + medium + hard)"
    else:
        levels = ["easy"]
        mode_description = "БЫСТРУЮ поверхностную (easy)"

    print("=" * 60)
    print("🛡️  MisconfigHunter — аудит безопасности конфигураций")
    print("=" * 60)
    print(f"📁 Проверяемая папка : {args.target}")
    print(f"🔎 Режим проверки    : {mode_description}")
    print("-" * 60)

    # Собственно запуск проверки. audit_project() сам находит нужные файлы
    # внутри target и прогоняет по ним проверки выбранных уровней.
    report = audit_project(path=args.target, levels=levels)

    print()
    print(report.summary())

    # Код возврата процесса: 1, если найдена хотя бы одна CRITICAL-находка —
    # удобно для использования в CI/CD как security gate.
    sys.exit(1 if report.critical_count > 0 else 0)


if __name__ == "__main__":
    main()