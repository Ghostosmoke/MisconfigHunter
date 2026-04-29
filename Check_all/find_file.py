from pathlib import Path
from collections import defaultdict
from typing import List , Dict , Any , Optional
from Easy_Check import all_easy_check
from Medium_Check import all_medium_check
from Hard_Check import all_hard_check
from found_files_need_check import rewrite_to_file
# ==================== КОНСТАНТЫ ====================
IGNORE_DIRS = {'.git' , 'node_modules' , '__pycache__' , 'venv' , '.venv' , 'dist' , 'build'}
TARGET_EXTENSIONS = {'.yaml' , '.yml' , '.json' , '.tf' , '.tfvars'}
TARGET_FILES = {'Dockerfile'}
MAX_FILE_SIZE_TO_READ = 5 * 1024 * 1024  # 5 МБ лимит для просмотра

# ==================== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ-КОНТЕЙНЕРЫ ====================
CURRENT_FOLDER_PATH: Optional[Path] = None
CURRENT_FOLDER_FILES: List[Path] = []
CURRENT_CHECK_RESULT: Optional[Any] = None
CURRENT_CHECK_ALL_RESULT: Optional[Any] = None

ALL_PROCESSED_FOLDERS: List[Path] = []
ALL_FOUND_FILES: List[Path] = []
ALL_CHECK_RESULTS: List[Any] = []
ALL_CHECK_ALL_RESULTS: List[Any] = []

LAST_CHECK_SUMMARY: Dict[str , Any] = {}


# ==================== ФУНКЦИИ ПОИСКА И СОРТИРОВКИ ====================

def find_config_files(root_path='.'):
    """Находит все конфигурационные файлы рекурсивно"""
    root = Path(root_path)
    found_files = []

    if not root.exists():
        print(f"❌ Путь не найден: {root}")
        return found_files

    for file in root.rglob('*'):
        if any(ignore in file.parts for ignore in IGNORE_DIRS):
            continue
        if file.is_file() and (file.name in TARGET_FILES or file.suffix in TARGET_EXTENSIONS):
            found_files.append(file)

    return found_files


def group_files_by_folder(files: List[Path]) -> Dict[Path , List[Path]]:
    """Группирует файлы по папкам для пакетной обработки"""
    files_by_folder = defaultdict(list)
    for file in files:
        files_by_folder[file.parent].append(file)
    return dict(files_by_folder)


def sort_by_name_hierarchical(files):
    """Иерархическая сортировка: папки → файлы внутри"""
    files_by_folder = defaultdict(list)
    for file in files:
        files_by_folder[file.parent].append(file)

    sorted_folders = sorted(files_by_folder.keys() , key=lambda f: str(f))
    result = []
    for folder in sorted_folders:
        sorted_files = sorted(files_by_folder[folder] , key=lambda f: f.name)
        result.extend(sorted_files)
    return result


def sort_by_size(files):
    """Сортирует файлы по размеру (от большего к меньшему)"""
    return sorted(files , key=lambda f: f.stat().st_size , reverse=True)


# ==================== ФУНКЦИИ ПРОСМОТРА ====================

def read_file_content(file_path):
    """Безопасно читает содержимое файла"""
    try:
        size = file_path.stat().st_size
        if size > MAX_FILE_SIZE_TO_READ:
            return f"⚠️ Файл слишком большой ({size / 1024 / 1024:.2f} МБ). Лимит: {MAX_FILE_SIZE_TO_READ / 1024 / 1024} МБ."

        encodings = ['utf-8' , 'utf-8-sig' , 'cp1251' , 'latin-1']
        content = None

        for enc in encodings:
            try:
                with open(file_path , 'r' , encoding=enc) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            return "❌ Не удалось прочитать файл (возможно, бинарный)."
        return content
    except Exception as e:
        return f"❌ Ошибка при чтении: {str(e)}"


def print_file_list_with_indices(files , title="Файлы"):
    """Выводит список файлов с номерами для выбора"""
    print(f"\n{title} ({len(files)}):")
    print("-" * 80)
    if not files:
        print("   (Файлы не найдены)")
        return

    current_folder = None
    for idx , file in enumerate(files , 1):
        folder = file.parent
        if folder != current_folder:
            print(f"\n📁 {folder}/")
            current_folder = folder
        print(f"   [{idx:>3}] {file.name}")
    print("-" * 80)


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
        size_str = f"{size} байт"
        if size > 1024:
            size_str = f"{size / 1024:.2f} КБ"
        if size > 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.2f} МБ"
        print(f"   {str(file.name):<50} {size_str:>10}")


# ==================== ЗАПУСК ВАШИХ ФУНКЦИЙ CHECK И CHECK_ALL ====================

def run_check(file_path: Path):
    """
    Запускает вашу функцию check() для одного файла.
    Сохраняет результат в глобальные переменные.
    """
    global CURRENT_CHECK_RESULT , ALL_CHECK_RESULTS

    print(f"\n🔍 Проверка файла: {file_path}")
    print("-" * 80)

    # ✅ ВЫЗОВ ВАШЕЙ ФУНКЦИИ check()
    print(files)
    # Вывод всех файлов по элементно
    # for i in files:
    #     print(i)
    result = all_easy_check(file_path)
    # result = 0
    # Сохраняем в переменные
    CURRENT_CHECK_RESULT = result
    ALL_CHECK_RESULTS.append(result)

    return result


def run_check_all(files: List[Path]):
    """
    Запускает вашу функцию check_all() для группы файлов.
    Сохраняет результат в глобальные переменные.
    """
    global CURRENT_CHECK_ALL_RESULT , ALL_CHECK_ALL_RESULTS

    print(f"\n{'=' * 80}")
    print(f"🛡️  КОМПЛЕКСНАЯ ПРОВЕРКА (check_all)")
    print(f"   Файлов для анализа: {len(files)}")
    print(f"{'=' * 80}")
    print(files)
    # ✅ ВЫЗОВ ВАШЕЙ ФУНКЦИИ check_all()
    # result = all_medium_check(files)

    # result = all_medium_check(files) + all_hard_check(files)


    result = 0
    # Сохраняем в переменные
    CURRENT_CHECK_ALL_RESULT = result
    ALL_CHECK_ALL_RESULTS.append(result)

    return result


def process_folder(folder_path: Path , files_in_folder: List[Path]):
    """
    Обрабатывает одну папку с файлами.
    Обновляет глобальные переменные-контейнеры.
    """
    global CURRENT_FOLDER_PATH , CURRENT_FOLDER_FILES
    global ALL_PROCESSED_FOLDERS , ALL_FOUND_FILES
    global LAST_CHECK_SUMMARY

    # Обновляем переменные текущей папки
    CURRENT_FOLDER_PATH = folder_path
    CURRENT_FOLDER_FILES = files_in_folder

    print(f"\n{'=' * 80}")
    print(f"📁 Обработка папки: {folder_path}")
    print(f"   Файлов в папке: {len(files_in_folder)}")
    print(f"{'=' * 80}")

    # 1. Запускаем check() для каждого файла
    for file_path in files_in_folder:
        run_check(file_path)

    # 2. Запускаем check_all() для всей группы файлов
    # run_check_all(files_in_folder)

    # 3. Накопление данных
    ALL_PROCESSED_FOLDERS.append(folder_path)
    ALL_FOUND_FILES.extend(files_in_folder)

    # 4. Обновление сводки
    LAST_CHECK_SUMMARY = {
        'folder': str(folder_path) ,
        'files_count': len(files_in_folder) ,
        'timestamp': str(Path.cwd())
    }


def process_all_folders(files: List[Path]):
    """
    Проходит по всем папкам с файлами.
    Переменные обновляются при каждой итерации.
    """
    files_by_folder = group_files_by_folder(files)

    print(f"\n🔍 Найдено папок с файлами: {len(files_by_folder)}")
    print(f"📄 Всего файлов: {len(files)}")

    # Очищаем накопленные данные
    global ALL_PROCESSED_FOLDERS , ALL_FOUND_FILES , ALL_CHECK_RESULTS , ALL_CHECK_ALL_RESULTS
    ALL_PROCESSED_FOLDERS = []
    ALL_FOUND_FILES = []
    ALL_CHECK_RESULTS = []
    ALL_CHECK_ALL_RESULTS = []

    # Проходим по каждой папке
    for folder_path , folder_files in files_by_folder.items():
        process_folder(folder_path , folder_files)

    # Финальная сводка
    print_final_summary()


def print_final_summary():
    """Выводит итоговую сводку по всем обработанным папкам"""
    print(f"\n{'=' * 80}")
    print("📊 ИТОГОВАЯ СВОДКА")
    print(f"{'=' * 80}")
    print(f"   Обработано папок: {len(ALL_PROCESSED_FOLDERS)}")
    print(f"   Всего файлов: {len(ALL_FOUND_FILES)}")
    print(f"   Результатов check(): {len(ALL_CHECK_RESULTS)}")
    print(f"   Результатов check_all(): {len(ALL_CHECK_ALL_RESULTS)}")
    # print(f"\n💡 Последняя проверенная папка: {LAST_CHECK_SUMMARY.get('folder' , 'N/A')}")
    print(f"{'=' * 80}")


def save_in_file(hierarchical_list , size_list , filename='found_files.txt'):
    """Сохранение результатов в файл"""
    try:
        with open(filename , 'w' , encoding='utf-8') as f:
            f.write("=== Иерархическая сортировка (папки → файлы) ===\n\n")
            current_folder = None
            for file in hierarchical_list:
                folder = file.parent
                if folder != current_folder:
                    f.write(f"\n{folder}/\n")
                    current_folder = folder
                f.write(f"   {file.name}\n")

            f.write("\n\n=== Сортировка по размеру ===\n\n")
            for file in size_list:
                size = file.stat().st_size
                f.write(f"{file} - {size} байт\n")

        print(f"\n💾 Результаты сохранены в {filename}")
    except Exception as e:
        print(f"\n❌ Ошибка при сохранении файла: {e}")


def view_file_interactive(files):
    """Интерактивный режим просмотра файлов"""
    if not files:
        print("\nНет файлов для просмотра.")
        return

    while True:
        print_file_list_with_indices(files , "📂 Доступные файлы для просмотра")
        print("\nМеню:")
        print("   Введите номер файла для просмотра")
        print("   's' - Сохранить список в файл")
        print("   'q' - Выход")

        choice = input("\nВаш выбор: ").strip().lower()

        if choice == 'q':
            print("\n👋 Выход из программы.")
            break

        if choice == 's':
            save_in_file(files , sort_by_size(files))
            continue

        try:
            idx = int(choice)
            if 1 <= idx <= len(files):
                selected_file = files[idx - 1]
                print(f"\n{'=' * 80}")
                print(f"📄 Чтение файла: {selected_file}")
                print(f"{'=' * 80}")
                content = read_file_content(selected_file)
                print(content)
                print(f"\n{'=' * 80}")
                input("Нажмите Enter, чтобы продолжить...")
            else:
                print("❌ Неверный номер файла.")
        except ValueError:
            print("❌ Введите число, 's' или 'q'.")


# ==================== ОСНОВНАЯ ПРОГРАММА ====================

if __name__ == '__main__':
    print("🔍 Поиск конфигурационных файлов...")
    print("🛡️  Запуск аудита безопасности...")
    print("=" * 80)

    # 1. Поиск файлов (поддерживает: .yaml, .yml, .json, .tf, .tfvars, Dockerfile)
    files = find_config_files('.')
    print(f"\n✅ Всего найдено файлов: {len(files)}")

    if not files:
        print("\n⚠️  Файлы не найдены. Проверьте параметры поиска.")
        exit(0)
    rewrite_to_file('')
    # 2. Обработка по папкам с запуском check() и check_all()
    process_all_folders(files)

    # 3. Сортировки для просмотра
    sorted_hierarchical = sort_by_name_hierarchical(files)
    sorted_by_size = sort_by_size(files)

    # 4. Интерактивный просмотр файлов
    # view_file_interactive(sorted_hierarchical)