from Check_all.find_file import find_config_files
from Check_all.core import CheckRegistry

def main():
    # 1️⃣ Находим все конфигурационные файлы
    print("🔍 Поиск конфигурационных файлов...")
    files = find_config_files('.')
    print(f"✅ Найдено файлов: {len(files)}")

    # 2️⃣ Запускаем проверки, передавая список файлов
    print("\n🚀 Запуск проверок безопасности...")
    reports_easy = CheckRegistry.run_all(level='easy', verbose=True, files=files)
    reports_medium = CheckRegistry.run_all(level='medium', verbose=True, files=files)
    reports_hard = CheckRegistry.run_all(level='hard' , verbose=True , files=files)
    # 3️⃣ Выводим сводку
    if reports_easy:
        CheckRegistry.print_summary(reports_easy)
    else:
        print("\n✅ Все проверки пройдены — уязвимостей не найдено!")

if __name__ == "__main__":
    main()