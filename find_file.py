from pathlib import Path
from collections import defaultdict

IGNORE_DIRS = {'.git' , 'node_modules' , '__pycache__' , 'venv' , '.venv' , 'dist' , 'build'}

TARGET_EXTENSIONS = {'.yaml' , '.yml' , '.json' , '.tf' , '.tfvars'}
TARGET_FILES = {'Dockerfile'}


def find_config_files(root_path='.'):
    """Находит все конфигурационные файлы рекурсивно"""
    root = Path(root_path)
    found_files = []

    for file in root.rglob('*'):
        if any(ignore in file.parts for ignore in IGNORE_DIRS):
            continue
        if file.name in TARGET_FILES or file.suffix in TARGET_EXTENSIONS:
            found_files.append(file)

    return found_files


def sort_by_name_hierarchical(files):
    """
    Иерархическая сортировка:
    1. Сначала сортируем папки по имени
    2. Внутри каждой папки сортируем файлы по имени
    """
    # Группируем файлы по папкам
    files_by_folder = defaultdict(list)

    for file in files:
        folder = file.parent
        files_by_folder[folder].append(file)

    # Сортируем папки по имени
    sorted_folders = sorted(files_by_folder.keys() , key=lambda f: str(f))

    # Собираем итоговый список
    result = []
    for folder in sorted_folders:
        # Сортируем файлы внутри папки
        sorted_files = sorted(files_by_folder[folder] , key=lambda f: f.name)
        result.extend(sorted_files)

    return result


def sort_by_size(files):
    """Сортирует файлы по размеру (от большего к меньшему)"""
    return sorted(files , key=lambda f: f.stat().st_size , reverse=True)


def print_files(files , title="Файлы"):
    """Красиво выводит список файлов"""
    print(f"\n{title} ({len(files)}):")
    print("-" * 80)
    current_folder = None
    for file in files:
        folder = file.parent
        # Показываем название папки только когда она меняется
        if folder != current_folder:
            print(f"\n📁 {folder}/")
            current_folder = folder
        print(f"   {file.name}")


def print_files_with_size(files , title="Файлы"):
    """Выводит файлы с указанием размера"""
    print(f"\n{title} ({len(files)}):")
    print("-" * 80)
    current_folder = None
    for file in files:
        folder = file.parent
        size = file.stat().st_size
        if folder != current_folder:
            print(f"\n📁 {folder}/")
            current_folder = folder
        print(f"   {str(file.name):<50} {size:>10} байт")

def save_in_file():
    # Сохранение результатов в файл
    with open('found_files.txt' , 'w' , encoding='utf-8') as f:
        f.write("=== Иерархическая сортировка (папки → файлы) ===\n\n")
        current_folder = None
        for file in sorted_hierarchical:
            folder = file.parent
            if folder != current_folder:
                f.write(f"\n{folder}/\n")
                current_folder = folder
            f.write(f"   {file.name}\n")

        f.write("\n\n=== Сортировка по размеру ===\n\n")
        for file in sorted_by_size:
            size = file.stat().st_size
            f.write(f"{file} - {size} байт\n")

    print("\n💾 Результаты сохранены в found_files.txt")

# ==================== ОСНОВНАЯ ПРОГРАММА ====================

if __name__ == '__main__':
    # Поиск файлов
    files = find_config_files('.')
    print(f"\n✅ Всего найдено файлов: {len(files)}")

    # Иерархическая сортировка по имени (папки → файлы внутри)
    sorted_hierarchical = sort_by_name_hierarchical(files)
    print_files(sorted_hierarchical , "📁 Иерархическая сортировка (папки → файлы)")

    # Сортировка по размеру
    sorted_by_size = sort_by_size(files)
    print_files_with_size(sorted_by_size , "📊 Сортировка по размеру")

