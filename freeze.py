import asyncio
import aiohttp
import hashlib
import re
import os
import secrets
import json
import base64
import time
from datetime import datetime
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError
from colorama import init, Fore, Style

init(autoreset=True)

ONLINE_DB_URL = "https://pzkfreeze-7dc92-default-rtdb.firebaseio.com"
ONLINE_DB_ENABLED = True

API_ID = 20749177
API_HASH = 'c4547190111b94e25c82a8f01d07ca43'

MASTER_KEY = None

def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
{Fore.CYAN}{'='*60}
{Fore.YELLOW}╔═══════════════════════════════════════════════════════╗
{Fore.YELLOW}║{Fore.RED}    ██████╗ ███████╗██╗  ██╗                           {Fore.YELLOW}║
{Fore.YELLOW}║{Fore.RED}    ██╔══██╗╚══███╔╝██║ ██╔╝                           {Fore.YELLOW}║
{Fore.YELLOW}║{Fore.RED}    ██████╔╝  ███╔╝ █████╔╝                            {Fore.YELLOW}║
{Fore.YELLOW}║{Fore.RED}    ██╔═══╝  ███╔╝  ██╔═██╗                            {Fore.YELLOW}║
{Fore.YELLOW}║{Fore.RED}    ██║     ███████╗██║  ██╗                           {Fore.YELLOW}║
{Fore.YELLOW}║{Fore.RED}    ╚═╝     ╚══════╝╚═╝  ╚═╝                           {Fore.YELLOW}║
{Fore.YELLOW}║{Fore.GREEN}       SESSION MANAGER v3.0 by fedolinov               {Fore.YELLOW}║
{Fore.YELLOW}╚═══════════════════════════════════════════════════════╝
{Fore.CYAN}{'='*60}{Style.RESET_ALL}
""")

def print_menu(title, options):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.YELLOW}{title.center(60)}")
    print(f"{Fore.CYAN}{'='*60}")
    for key, value in options.items():
        print(f"{Fore.GREEN}[{key}] {Fore.WHITE}{value}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def print_success(msg):
    print(f"{Fore.GREEN}✅ {msg}{Style.RESET_ALL}")

def print_error(msg):
    print(f"{Fore.RED}❌ {msg}{Style.RESET_ALL}")

def print_warning(msg):
    print(f"{Fore.YELLOW}⚠️  {msg}{Style.RESET_ALL}")

def print_info(msg):
    print(f"{Fore.CYAN}ℹ️  {msg}{Style.RESET_ALL}")

async def firebase_request(method, endpoint, data=None, token=None):
    if not ONLINE_DB_ENABLED:
        return None

    try:
        url = f"{ONLINE_DB_URL}/{endpoint}.json"
        if token:
            url += f"?auth={token}"

        timeout = aiohttp.ClientTimeout(total=10)
        headers = {'Content-Type': 'application/json'}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            if method == 'GET':
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.json()
            elif method == 'POST':
                async with session.post(url, json=data) as response:
                    if response.status == 200:
                        return await response.json()
            elif method == 'PUT':
                async with session.put(url, json=data) as response:
                    if response.status == 200:
                        return await response.json()
            elif method == 'DELETE':
                async with session.delete(url) as response:
                    if response.status == 200:
                        return await response.json()
            elif method == 'PATCH':
                async with session.patch(url, json=data) as response:
                    if response.status == 200:
                        return await response.json()
    except Exception as e:
        return None

    return None

class EncryptionManager:
    @staticmethod
    def generate_master_key():
        return secrets.token_hex(16)

    @staticmethod
    def encrypt_data(key, data):
        try:
            if not key or not data:
                return None
            simple_key = hashlib.sha256(key.encode()).digest()[:16]
            data_bytes = data.encode('utf-8')
            
            result = []
            for i in range(len(data_bytes)):
                result.append(data_bytes[i] ^ simple_key[i % len(simple_key)])
            
            encrypted = bytes(result)
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print_error(f"Ошибка шифрования: {e}")
            return None

    @staticmethod
    def decrypt_data(key, encrypted_data):
        try:
            if not key or not encrypted_data:
                return None
            simple_key = hashlib.sha256(key.encode()).digest()[:16]
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
            
            result = []
            for i in range(len(encrypted_bytes)):
                result.append(encrypted_bytes[i] ^ simple_key[i % len(simple_key)])
            
            decrypted = bytes(result)
            return decrypted.decode('utf-8', errors='ignore')
        except Exception as e:
            return None

    @staticmethod
    def simple_encrypt(data):
        try:
            return base64.b64encode(data.encode()).decode('utf-8')
        except:
            return None

    @staticmethod
    def simple_decrypt(data):
        try:
            return base64.b64decode(data).decode('utf-8')
        except:
            return None

class FirebaseDatabase:
    def __init__(self):
        self.firebase_available = False
        self.current_user_id = None
        self.current_user_token = None
        self.user_cipher = None
        self.check_firebase_connection()

    def check_firebase_connection(self):
        if not ONLINE_DB_ENABLED:
            return False

        try:
            import urllib.request
            req = urllib.request.Request(f"{ONLINE_DB_URL}/.json", method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    self.firebase_available = True
                    return True
        except Exception as e:
            self.firebase_available = False

        return False

    async def initialize_encryption(self):
        global MASTER_KEY

        print_info("🔐 Инициализация шифрования...")
        
        encryption_data = await firebase_request('GET', 'system/encryption')
        
        if encryption_data is None or 'key' not in encryption_data:
            MASTER_KEY = EncryptionManager.generate_master_key()
            print_info(f"Создан новый ключ: {MASTER_KEY[:8]}...")
            
            encryption_config = {
                'key': MASTER_KEY,
                'created_at': datetime.now().isoformat()
            }
            
            result = await firebase_request('PUT', 'system/encryption', encryption_config)
            if result is not None:
                print_success("✅ Система шифрования инициализирована")
                return True
            else:
                print_error("❌ Ошибка сохранения шифрования")
                return False
        else:
            key_string = encryption_data.get('key')
            if key_string:
                MASTER_KEY = key_string
                print_success(f"✅ Система шифрования загружена")
                return True
            else:
                print_error("❌ Ключ шифрования не найден")
                return False

    async def load_user_encryption(self, password):
        try:
            self.user_cipher = hashlib.sha256(password.encode()).hexdigest()
            return True
        except Exception as e:
            return False

    async def check_root_exists(self):
        result = await firebase_request('GET', 'system/root')
        return result is not None

    async def create_root_user(self, password):
        if not MASTER_KEY:
            print_error("❌ Шифрование не инициализировано")
            return False

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        encrypted_password = EncryptionManager.encrypt_data(MASTER_KEY, password_hash)

        if not encrypted_password:
            print_error("❌ Ошибка шифрования пароля")
            return False

        root_data = {
            'password_encrypted': encrypted_password,
            'created_at': datetime.now().isoformat(),
            'is_active': True
        }

        result = await firebase_request('PUT', 'system/root', root_data)
        return result is not None

    async def verify_root_password(self, password):
        if not MASTER_KEY:
            return False

        root_data = await firebase_request('GET', 'system/root')
        if not root_data:
            return False

        encrypted_password = root_data.get('password_encrypted')
        if not encrypted_password:
            return False

        decrypted_hash = EncryptionManager.decrypt_data(MASTER_KEY, encrypted_password)
        if not decrypted_hash:
            return False

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return decrypted_hash == password_hash

    async def user_exists(self, username):
        if not MASTER_KEY:
            return False

        users_data = await firebase_request('GET', 'users')
        if not users_data:
            return False

        for user_id, encrypted_data in users_data.items():
            if not encrypted_data:
                continue

            encrypted_username = encrypted_data.get('username_encrypted')
            if not encrypted_username:
                continue

            decrypted_username = EncryptionManager.decrypt_data(MASTER_KEY, encrypted_username)
            if decrypted_username == username:
                return True

        return False

    async def register_user(self, username, password):
        if not self.firebase_available:
            print_error("❌ База данных недоступна")
            return None

        if await self.user_exists(username):
            print_error("❌ Пользователь с таким логином уже существует")
            return None

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user_id = secrets.token_hex(16)
        access_token = secrets.token_hex(32)

        if not MASTER_KEY:
            print_error("❌ MASTER_KEY не установлен")
            return None

        print_info(f"Шифрование данных для пользователя: {username}")
        
        encrypted_username = EncryptionManager.encrypt_data(MASTER_KEY, username)
        print_info(f"Зашифровано имя: {encrypted_username[:20]}...")
        
        encrypted_password = EncryptionManager.encrypt_data(MASTER_KEY, password_hash)
        print_info(f"Зашифрован пароль: {encrypted_password[:20]}...")
        
        encrypted_token = EncryptionManager.encrypt_data(MASTER_KEY, access_token)
        print_info(f"Зашифрован токен: {encrypted_token[:20]}...")

        if not encrypted_username:
            print_error("❌ Ошибка: encrypted_username is None")
        if not encrypted_password:
            print_error("❌ Ошибка: encrypted_password is None")
        if not encrypted_token:
            print_error("❌ Ошибка: encrypted_token is None")

        if not all([encrypted_username, encrypted_password, encrypted_token]):
            print_error("❌ Ошибка шифрования данных")
            return None

        user_data = {
            'username_encrypted': encrypted_username,
            'password_encrypted': encrypted_password,
            'user_id': user_id,
            'access_token_encrypted': encrypted_token,
            'created_at': datetime.now().isoformat(),
            'last_login': datetime.now().isoformat(),
            'failed_attempts': 0,
            'is_locked': False
        }

        print_info("Отправка данных в Firebase...")
        result = await firebase_request('PUT', f'users/{user_id}', user_data)

        if result is not None:
            self.current_user_id = user_id
            self.current_user_token = access_token
            await self.load_user_encryption(password)
            print_success(f"✅ Пользователь {username} успешно зарегистрирован")
            return user_id
        else:
            print_error("❌ Ошибка при сохранении в Firebase")
            return None

    async def login_user(self, username, password):
        if not self.firebase_available or not MASTER_KEY:
            print_error("❌ Система не готова")
            return None

        users_data = await firebase_request('GET', 'users')
        if not users_data:
            print_error("❌ Пользователи не найдены")
            return None

        for user_id, encrypted_data in users_data.items():
            if not encrypted_data:
                continue

            if encrypted_data.get('is_locked'):
                failed_attempts = encrypted_data.get('failed_attempts', 0)
                if failed_attempts >= 5:
                    print_error("❌ Аккаунт заблокирован")
                    continue

            encrypted_username = encrypted_data.get('username_encrypted')
            encrypted_password = encrypted_data.get('password_encrypted')
            encrypted_token = encrypted_data.get('access_token_encrypted')

            if not all([encrypted_username, encrypted_password, encrypted_token]):
                continue

            decrypted_username = EncryptionManager.decrypt_data(MASTER_KEY, encrypted_username)
            decrypted_password_hash = EncryptionManager.decrypt_data(MASTER_KEY, encrypted_password)
            decrypted_token = EncryptionManager.decrypt_data(MASTER_KEY, encrypted_token)

            if not all([decrypted_username, decrypted_password_hash, decrypted_token]):
                continue

            if decrypted_username == username:
                password_hash = hashlib.sha256(password.encode()).hexdigest()

                if decrypted_password_hash == password_hash:
                    if await self.load_user_encryption(password):
                        self.current_user_id = user_id
                        self.current_user_token = decrypted_token

                        update_data = {
                            'last_login': datetime.now().isoformat(),
                            'failed_attempts': 0
                        }

                        await firebase_request('PATCH', f'users/{user_id}', update_data)
                        return user_id
                    else:
                        return None
                else:
                    failed_attempts = encrypted_data.get('failed_attempts', 0) + 1
                    update_data = {'failed_attempts': failed_attempts}

                    if failed_attempts >= 5:
                        update_data['is_locked'] = True

                    await firebase_request('PATCH', f'users/{user_id}', update_data)
                    return None

        return None

    async def check_channel_subscription(self, client):
        print_info("🔍 Проверка подписки на канал hacking 2307...")

        try:
            channel_names = ['hacking 2307', 'hacking2307', '#JakesDev #FT']
            dialogs = await client.get_dialogs(limit=100)

            for dialog in dialogs:
                dialog_name = dialog.name or ""
                dialog_title = dialog.title or ""

                dialog_name_lower = dialog_name.lower()
                dialog_title_lower = dialog_title.lower()

                for channel_name in channel_names:
                    if channel_name in dialog_name_lower or channel_name in dialog_title_lower:
                        print_success(f"✅ Найден канал: {dialog_name or dialog_title}")
                        return True

            print_error("❌ Канал hacking 2307 не найден в ваших диалогах")
            return False

        except Exception as e:
            print_error(f"❌ Ошибка проверки подписки: {e}")
            return False

    async def save_session(self, user_id, session_name, phone, session_string, client=None):
        if not self.firebase_available or not self.user_cipher:
            return False

        if not self.current_user_id or self.current_user_id != user_id:
            return False

        if client:
            if not await self.check_channel_subscription(client):
                print_error("❌ Вы не подписаны на канал hacking 2307")
                print_info("⚠️  Сессия НЕ будет сохранена")
                return False

            print_success("✅ Проверка подписки пройдена!")

        session_id = secrets.token_hex(16)

        encrypted_session_name = EncryptionManager.encrypt_data(self.user_cipher, session_name)
        encrypted_phone = EncryptionManager.encrypt_data(self.user_cipher, phone)
        encrypted_session = EncryptionManager.encrypt_data(self.user_cipher, session_string)

        if not all([encrypted_session_name, encrypted_phone, encrypted_session]):
            print_error("❌ Ошибка шифрования данных сессии")
            return False

        session_data = {
            'session_name_encrypted': encrypted_session_name,
            'phone_encrypted': encrypted_phone,
            'session_string_encrypted': encrypted_session,
            'user_id': user_id,
            'created_at': datetime.now().isoformat(),
            'last_used': datetime.now().isoformat(),
            'session_id': session_id,
            'verified': True
        }

        result = await firebase_request('PUT', f'sessions/{session_id}', session_data)
        return result is not None

    async def delete_session(self, user_id, session_id):
        if not self.firebase_available:
            return False

        if not self.current_user_id or self.current_user_id != user_id:
            return False

        session_data = await firebase_request('GET', f'sessions/{session_id}')
        if not session_data or session_data.get('user_id') != user_id:
            return False

        result = await firebase_request('DELETE', f'sessions/{session_id}')
        return result is not None

    async def get_user_sessions(self, user_id):
        if not self.firebase_available or not self.user_cipher:
            return []

        if not self.current_user_id or self.current_user_id != user_id:
            return []

        sessions_data = await firebase_request('GET', 'sessions')
        user_sessions = []

        if sessions_data:
            for session_id, encrypted_data in sessions_data.items():
                if not encrypted_data or encrypted_data.get('user_id') != user_id:
                    continue

                encrypted_name = encrypted_data.get('session_name_encrypted')
                encrypted_phone = encrypted_data.get('phone_encrypted')

                if not encrypted_name or not encrypted_phone:
                    continue

                session_name = EncryptionManager.decrypt_data(self.user_cipher, encrypted_name)
                phone = EncryptionManager.decrypt_data(self.user_cipher, encrypted_phone)

                if session_name and phone:
                    user_sessions.append({
                        'id': session_id,
                        'session_name': session_name,
                        'phone': phone,
                        'created_at': encrypted_data.get('created_at', ''),
                        'session_id': encrypted_data.get('session_id', session_id),
                        'verified': encrypted_data.get('verified', False)
                    })

        return user_sessions

    async def get_session_string(self, user_id, session_id):
        if not self.firebase_available or not self.user_cipher:
            return ''

        if not self.current_user_id or self.current_user_id != user_id:
            return ''

        session_data = await firebase_request('GET', f'sessions/{session_id}')
        if not session_data or session_data.get('user_id') != user_id:
            return ''

        encrypted_session = session_data.get('session_string_encrypted')
        if not encrypted_session:
            return ''

        return EncryptionManager.decrypt_data(self.user_cipher, encrypted_session)

async def create_root_user_flow(db):
    print_header()
    print_menu("СОЗДАНИЕ ROOT АДМИНИСТРАТОРА", {
        "info": "Добавление root пользователя для доступа к настройкам БД"
    })

    if not db.firebase_available:
        print_error("Ошибка подключения к базе данных")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    root_exists = await db.check_root_exists()
    if root_exists:
        print_error("Root администратор уже создан")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    print_info("Root администратор нужен для доступа к настройкам системы и БД")
    print_info("Создается только один раз")

    password = input(f"\n{Fore.CYAN}Введите пароль для root администратора: {Fore.WHITE}")
    if len(password) < 6:
        print_error("Пароль должен быть не менее 6 символов")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    confirm = input(f"{Fore.CYAN}Подтвердите пароль: {Fore.WHITE}")
    if password != confirm:
        print_error("Пароли не совпадают")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    success = await db.create_root_user(password)
    if success:
        print_success("Root администратор успешно создан!")
        print_info("Теперь вы можете использовать все функции системы")
    else:
        print_error("Ошибка создания root администратора")

    input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
    return success

async def verify_root_password_flow(db):
    print_header()
    print_menu("ДОСТУП К НАСТРОЙКАМ БД", {
        "info": "Требуется root пароль для доступа к настройкам системы"
    })

    password = input(f"{Fore.CYAN}Введите root пароль: {Fore.WHITE}")

    if await db.verify_root_password(password):
        print_success("Доступ разрешен")
        return True
    else:
        print_error("Неверный пароль")
        return False

async def register_user_flow(db):
    print_header()
    print_menu("РЕГИСТРАЦИЯ", {
        "info": "Создание нового аккаунта"
    })

    if not db.firebase_available:
        print_error("Ошибка подключения")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    username = input(f"\n{Fore.CYAN}Введите логин: {Fore.WHITE}")
    if not username:
        print_error("Логин не может быть пустым")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    if await db.user_exists(username):
        print_error("❌ Пользователь с таким логином уже существует")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    password = input(f"{Fore.CYAN}Введите пароль: {Fore.WHITE}")
    if len(password) < 4:
        print_error("Пароль должен быть не менее 4 символов")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

    user_id = await db.register_user(username, password)
    if user_id:
        print_success("Регистрация успешна")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return True
    else:
        print_error("Ошибка регистрации")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return False

async def login_user_flow(db):
    print_header()
    print_menu("ВХОД В СИСТЕМУ", {
        "info": "Авторизация"
    })

    if not db.firebase_available:
        print_error("Ошибка подключения")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return None

    username = input(f"\n{Fore.CYAN}Логин: {Fore.WHITE}")
    password = input(f"{Fore.CYAN}Пароль: {Fore.WHITE}")

    user_id = await db.login_user(username, password)

    if user_id:
        print_success("Вход выполнен")
        await asyncio.sleep(1)
        return user_id
    else:
        print_error("Неверный логин или пароль")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return None

async def freeze_session_flow(db, user_id):
    print_header()
    print_menu("ДОБАВЛЕНИЕ СЕССИИ", {
        "info": "Привязка аккаунта Telegram"
    })

    if not db.firebase_available:
        print_error("Ошибка подключения")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    session_name = input(f"\n{Fore.CYAN}Введите название сессии: {Fore.WHITE}")
    if not session_name:
        session_name = f"Сессия_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    phone = input(f"{Fore.CYAN}Введите номер телефона (+79123456789): {Fore.WHITE}").strip()
    if not phone.startswith('+'):
        phone = '+' + phone

    session = StringSession()
    client = TelegramClient(session, API_ID, API_HASH)

    try:
        await client.connect()

        print_info(f"Отправка кода подтверждения на {phone}...")

        sent_code = await client.send_code_request(phone)

        while True:
            code = input(f"\n{Fore.CYAN}Введите 5-значный код из Telegram: {Fore.WHITE}").strip()
            if code.isdigit() and len(code) == 5:
                break
            print_error("Код должен содержать 5 цифр")

        try:
            await client.sign_in(phone=phone, code=code)
            print_success("Код принят!")
        except SessionPasswordNeededError:
            cloud_password = input(f"{Fore.CYAN}Введите облачный пароль: {Fore.WHITE}")
            await client.sign_in(password=cloud_password)
            print_success("Облачный пароль принят!")
        except PhoneCodeInvalidError:
            print_error("Неверный код подтверждения")
            await client.disconnect()
            return

        if await client.is_user_authorized():
            me = await client.get_me()
            print_success(f"Успешный вход как: {me.first_name}")

            print_info("\n" + "="*60)
            print_info("🔒 ПРОВЕРКА ТРЕБОВАНИЙ СИСТЕМЫ")
            print_info("="*60)
            print_info("Для использования системы необходимо:")
            print_info("1. Быть подписанным на канал hacking 2307")
            print_info("2. Проверка осуществляется по списку ваших диалогов")
            print_info("="*60)

            session_string = session.save()

            if await db.save_session(user_id, session_name, phone, session_string, client):
                print_success(f"\n✅ Сессия '{session_name}' успешно сохранена!")
                print_info("🔥 Теперь вы можете использовать все функции системы")
            else:
                print_error("\n❌ Сессия не сохранена")
                print_info("Причина: не пройдена проверка подписки на канал hacking 2307")
        else:
            print_error("Не удалось авторизоваться")

    except Exception as e:
        print_error(f"Ошибка: {e}")
    finally:
        await client.disconnect()

    input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")

async def delete_session_flow(db, user_id):
    print_header()
    print_menu("УДАЛЕНИЕ СЕССИИ", {
        "info": "Удаление сохраненной сессии"
    })

    if not db.firebase_available:
        print_error("Ошибка подключения")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    sessions = await db.get_user_sessions(user_id)

    if not sessions:
        print_error("Нет сохраненных сессий")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.YELLOW}{'ВЫБЕРИТЕ СЕССИЮ':^70}")
    print(f"{Fore.CYAN}{'='*70}")

    for idx, session in enumerate(sessions, 1):
        verified = "✅" if session.get('verified') else "❌"
        print(f"{Fore.GREEN}[{idx}]{Fore.WHITE} {session['session_name']} ({session['phone']}) {verified}")

    print(f"{Fore.CYAN}{'='*70}")

    try:
        choice = int(input(f"\n{Fore.CYAN}Выберите сессию (1-{len(sessions)}): {Fore.WHITE}"))
        if 1 <= choice <= len(sessions):
            selected_session = sessions[choice-1]

            confirm = input(f"\n{Fore.RED}Удалить сессию '{selected_session['session_name']}'? (y/n): {Fore.WHITE}")
            if confirm.lower() == 'y':
                if await db.delete_session(user_id, selected_session['id']):
                    print_success("Сессия удалена!")
                else:
                    print_error("Ошибка удаления")
            else:
                print_info("Отменено")
        else:
            print_error("Неверный выбор")
    except ValueError:
        print_error("Неверный ввод")

    input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")

async def restore_session_flow(db, user_id):
    print_header()
    print_menu("ВОССТАНОВЛЕНИЕ ДОСТУПА", {
        "info": "Получение кода подтверждения"
    })

    if not db.firebase_available:
        print_error("Ошибка подключения")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    sessions = await db.get_user_sessions(user_id)

    if not sessions:
        print_error("Нет сохраненных сессий")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    verified_sessions = [s for s in sessions if s.get('verified', False)]

    if not verified_sessions:
        print_error("Нет проверенных сессий")
        print_info("Для восстановления доступа нужна сессия с подтвержденной подпиской")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    print(f"\n{Fore.CYAN}Выберите сессию:{Style.RESET_ALL}")

    for idx, session in enumerate(verified_sessions, 1):
        print(f"{Fore.GREEN}[{idx}]{Fore.WHITE} {session['session_name']} ({session['phone']}) ✅")

    try:
        choice = int(input(f"\n{Fore.CYAN}Номер сессии (1-{len(verified_sessions)}): {Fore.WHITE}"))
        if 1 <= choice <= len(verified_sessions):
            selected_session = verified_sessions[choice-1]
        else:
            print_error("Неверный выбор")
            return
    except ValueError:
        print_error("Неверный ввод")
        return

    session_string = await db.get_session_string(user_id, selected_session['id'])

    if not session_string:
        print_error("Ошибка получения сессии")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    print_info(f"Восстановление: {selected_session['session_name']}")

    session = StringSession(session_string)
    client = TelegramClient(session, API_ID, API_HASH)

    code_found = None

    @client.on(events.NewMessage(incoming=True))
    async def handler(event):
        nonlocal code_found
        message_text = event.message.text or ""

        codes = re.findall(r'\b\d{5}\b', message_text)

        if codes and ('telegram' in message_text.lower() or 'код' in message_text.lower()):
            code_found = codes[0]
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f"{Fore.YELLOW}КОД ОБНАРУЖЕН!")
            print(f"{Fore.CYAN}От: {event.sender_id}")
            print(f"{Fore.GREEN}КОД: {code_found}")
            print(f"{Fore.GREEN}{'='*60}")
            await client.disconnect()

    try:
        await client.connect()

        if not await client.is_user_authorized():
            print_error("Сессия невалидна")
            await client.disconnect()
            return

        me = await client.get_me()
        print_success(f"Авторизован как: {me.first_name}")

        print_info("Ожидание кода...")
        print_info("Отправьте код входа на этот аккаунт")
        print_warning("Ожидание 60 секунд...")

        try:
            await asyncio.wait_for(client.run_until_disconnected(), timeout=60)
        except asyncio.TimeoutError:
            print_warning("Время истекло")

        if code_found:
            print_success(f"Код: {code_found}")
        else:
            print_error("Код не получен")

    except KeyboardInterrupt:
        print_info("Остановлено")
    except Exception as e:
        print_error(f"Ошибка: {e}")
    finally:
        await client.disconnect()

    input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")

async def list_sessions_flow(db, user_id):
    print_header()
    print_menu("ВАШИ СЕССИИ", {
        "info": "Просмотр всех сессий"
    })

    if not db.firebase_available:
        print_error("Ошибка подключения")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    sessions = await db.get_user_sessions(user_id)

    if not sessions:
        print_error("Нет сохраненных сессий")
        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        return

    verified_sessions = [s for s in sessions if s.get('verified', False)]
    unverified_sessions = [s for s in sessions if not s.get('verified', False)]

    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"{Fore.YELLOW}{'ВАШИ СЕССИИ':^80}")
    print(f"{Fore.CYAN}{'='*80}")
    print(f"{Fore.GREEN}{'№':<3} {'Название':<20} {'Телефон':<15} {'Дата':<20} {'Статус':<10}")
    print(f"{Fore.CYAN}{'-'*80}")

    idx = 1
    all_sessions = verified_sessions + unverified_sessions

    for session in all_sessions:
        if session['created_at']:
            try:
                dt = datetime.fromisoformat(session['created_at'].replace('Z', '+00:00'))
                date_str = dt.strftime('%d.%m.%Y %H:%M')
            except:
                date_str = session['created_at'][:16]
        else:
            date_str = "неизвестно"

        status = "✅" if session.get('verified', False) else "❌"
        status_text = "Проверена" if session.get('verified', False) else "Не проверена"

        print(f"{Fore.GREEN}{idx:<3} {Fore.WHITE}{session['session_name']:<20} "
              f"{Fore.CYAN}{session['phone']:<15} "
              f"{Fore.YELLOW}{date_str:<20} {Fore.GREEN if session.get('verified', False) else Fore.RED}{status} {status_text}")
        idx += 1

    print(f"{Fore.CYAN}{'='*80}")

    print(f"\n{Fore.MAGENTA}Статистика:")
    print(f"{Fore.GREEN}Всего сессий: {len(sessions)}")
    print(f"{Fore.GREEN}Проверенных: {len(verified_sessions)}")
    print(f"{Fore.RED}Непроверенных: {len(unverified_sessions)}")

    if unverified_sessions:
        print(f"\n{Fore.YELLOW}⚠️  Непроверенные сессии не могут быть использованы")
        print(f"{Fore.YELLOW}   Для проверки нужно добавить сессию заново и подтвердить подписку")

    input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")

async def settings_menu(db, user_id):
    print_header()
    print_menu("НАСТРОЙКИ СИСТЕМЫ", {
        "1": "Настройки базы данных (root доступ)",
        "2": "Проверка подключения",
        "0": "Назад"
    })

    choice = input(f"\n{Fore.CYAN}Выберите действие (0-2): {Fore.WHITE}")

    if choice == '1':
        if not await verify_root_password_flow(db):
            input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
            return

        print_header()
        print_menu("НАСТРОЙКИ БАЗЫ ДАННЫХ", {
            "1": "Изменить root пароль",
            "2": "Статистика системы",
            "3": "Очистка базы данных",
            "0": "Назад"
        })

        sub_choice = input(f"\n{Fore.CYAN}Выберите действие (0-3): {Fore.WHITE}")

        if sub_choice == '1':
            print_header()
            print_menu("СМЕНА ROOT ПАРОЛЯ", {})

            old_password = input(f"{Fore.CYAN}Введите текущий пароль: {Fore.WHITE}")
            if not await db.verify_root_password(old_password):
                print_error("Неверный пароль")
                input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
                return

            new_password = input(f"{Fore.CYAN}Введите новый пароль: {Fore.WHITE}")
            if len(new_password) < 6:
                print_error("Пароль должен быть не менее 6 символов")
                input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
                return

            confirm = input(f"{Fore.CYAN}Подтвердите новый пароль: {Fore.WHITE}")
            if new_password != confirm:
                print_error("Пароли не совпадают")
                input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
                return

            success = await db.create_root_user(new_password)
            if success:
                print_success("Пароль изменен")
            else:
                print_error("Ошибка изменения пароля")

            input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        elif sub_choice == '2':
            print_header()
            print_menu("СТАТИСТИКА СИСТЕМЫ", {})

            users = await firebase_request('GET', 'users')
            sessions = await firebase_request('GET', 'sessions')

            verified_sessions = 0
            unverified_sessions = 0

            if sessions:
                for session_id, session_data in sessions.items():
                    if session_data and session_data.get('verified'):
                        verified_sessions += 1
                    else:
                        unverified_sessions += 1

            if users:
                print_info(f"Пользователей: {len(users)}")
            else:
                print_info("Пользователей: 0")

            if sessions:
                print_info(f"Всего сессий: {len(sessions)}")
                print_info(f"Проверенных: {verified_sessions}")
                print_info(f"Непроверенных: {unverified_sessions}")
            else:
                print_info("Сессий: 0")

            input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
        elif sub_choice == '3':
            print_header()
            print_menu("ОЧИСТКА БАЗЫ ДАННЫХ", {
                "info": "⚠️  УДАЛЕНИЕ ВСЕХ ДАННЫХ  ⚠️"
            })

            confirm = input(f"{Fore.RED}Очистить ВСЕ данные? (yes/no): {Fore.WHITE}")
            if confirm.lower() == 'yes':
                users = await firebase_request('GET', 'users')
                if users:
                    for user_id in users.keys():
                        await firebase_request('DELETE', f'users/{user_id}')

                sessions = await firebase_request('GET', 'sessions')
                if sessions:
                    for session_id in sessions.keys():
                        await firebase_request('DELETE', f'sessions/{session_id}')

                print_success("Данные очищены")
            else:
                print_info("Отменено")

            input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
    elif choice == '2':
        print_header()
        print_menu("ПРОВЕРКА ПОДКЛЮЧЕНИЯ", {})

        if db.firebase_available:
            print_success("База данных доступна")
            test_data = {'test': datetime.now().isoformat()}
            result = await firebase_request('POST', 'test', test_data)

            if result:
                print_success("Запись успешна")
                if 'name' in result:
                    await firebase_request('DELETE', f"test/{result['name']}")
            else:
                print_warning("Ошибка записи")
        else:
            print_error("База данных недоступна")

        input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")

async def main_menu_flow(db, user_id):
    while True:
        print_header()
        print_menu("ГЛАВНОЕ МЕНЮ", {
            "1": "Добавить сессию Telegram",
            "2": "Удалить сессию",
            "3": "Восстановить доступ",
            "4": "Показать все сессии",
            "5": "Настройки системы",
            "0": "Выйти"
        })

        choice = input(f"\n{Fore.CYAN}Выберите действие (0-5): {Fore.WHITE}")

        if choice == '1':
            await freeze_session_flow(db, user_id)
        elif choice == '2':
            await delete_session_flow(db, user_id)
        elif choice == '3':
            await restore_session_flow(db, user_id)
        elif choice == '4':
            await list_sessions_flow(db, user_id)
        elif choice == '5':
            await settings_menu(db, user_id)
        elif choice == '0':
            print_info("Выход...")
            await asyncio.sleep(1)
            break
        else:
            print_error("Неверный выбор")
            await asyncio.sleep(1)

async def main():
    print_header()
    print_info("🚀 Запуск Session Manager v3.0")
    
    db = FirebaseDatabase()

    if not db.firebase_available:
        print_error("❌ Ошибка подключения к базе данных")
        print_info("⚠️  Проверьте подключение к интернету")
        input(f"\n{Fore.YELLOW}Нажмите Enter для выхода...")
        return

    encryption_ok = await db.initialize_encryption()
    if not encryption_ok:
        print_error("❌ Ошибка инициализации системы шифрования")
        print_info("⚠️  Попробуйте очистить базу данных")
        input(f"\n{Fore.YELLOW}Нажмите Enter для выхода...")
        return

    while True:
        print_header()
        print_menu("ГЛАВНОЕ МЕНЮ", {
            "1": "Войти в аккаунт",
            "2": "Зарегистрироваться",
            "3": "Добавить аккаунт администратора",
            "0": "Выход"
        })

        choice = input(f"\n{Fore.CYAN}Выберите действие (0-3): {Fore.WHITE}")

        if choice == '1':
            user_id = await login_user_flow(db)
            if user_id:
                await main_menu_flow(db, user_id)
        elif choice == '2':
            await register_user_flow(db)
        elif choice == '3':
            await create_root_user_flow(db)
        elif choice == '0':
            print_info("Выход...")
            break
        else:
            print_error("Неверный выбор")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Остановлено")
    except Exception as e:
        print(f"\n{Fore.RED}Ошибка: {e}")
        import traceback
        traceback.print_exc()
        input(f"\n{Fore.YELLOW}Нажмите Enter для выхода...")
