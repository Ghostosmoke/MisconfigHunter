def write_to_file(data , filename='found_files_need_check.txt'):
    """
    Записывает данные в файл, каждый раз перезаписывая содержимое.
    """
    with open(filename , 'a' , encoding='utf-8') as f:
        f.write(str(data))
        f.write('\n\n')
        f.write('='*100 + '\n' * 5)

    print(f"✅ Данные записаны в {filename}")
def rewrite_to_file(data , filename='found_files_need_check.txt'):
    """
    Записывает данные в файл, каждый раз перезаписывая содержимое.
    """
    with open(filename , 'w' , encoding='utf-8') as f:
        f.write(str(data))

    print(f"✅ Данные записаны в {filename}")