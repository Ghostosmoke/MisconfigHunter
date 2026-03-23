import yaml
from yaml.loader import SafeLoader
# документ YAML
yml = """
---
  UserName: Alicia
  Password: pinga123* 
  phone: (495) 555-32-56
  room: 10
  TablesList:
        - EmployeeTable
        - SoftwaresList
        - HardwareList 
...
"""
# читаем документ YAML
data = yaml.load(yml, Loader=SafeLoader)
# смотрим, что получилось
print(data)
# {'UserName': 'Alicia', 'Password': 'pinga123*',
# 'phone': '(495) 555-32-56', 'room': 10,
# 'TablesList': ['EmployeeTable', 'SoftwaresList', 'HardwareList']}

with open('1.yml') as f:
    # читаем документ YAML
    data = yaml.load(f, Loader=SafeLoader)
    print(data)