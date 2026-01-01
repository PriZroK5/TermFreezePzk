# PZK SESSION MANAGER Termux v3.0

![Version](https://img.shields.io/badge/version-3.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

<div align="center">
  
# 🚀 PZK SESSION MANAGER

**🔥 Мощный менеджер Telegram-сессий с облачным хранилищем**

📢 *Написано специально для канала hacking 2307*  
👨💻 *Создатель софта: @Fedolinov*

</div>

## 📦 Установка в Termux

```bash
# Обновление пакетов
pkg update && pkg upgrade -y

# Установка Python и Git
pkg install python git -y

# Клонирование репозитория
git clone https://github.com/PriZroK5/pezlo-session-manager.git

# Переход в папку проекта
cd pezlo-session-manager

# Установка зависимостей
pip install -r requirements.txt

# Запуск программы
python3 freeze.py
