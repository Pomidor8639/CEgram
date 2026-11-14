# CEgram

[![Language](https://img.shields.io/badge/Language-C89%20%2F%20C99-00599C.svg?style=flat-square&logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/Platform-Windows%20CE%20%7C%20Windows%20Mobile-0078D7.svg?style=flat-square&logo=windows)](https://en.wikipedia.org/wiki/Windows_CE)
[![Protocol](https://img.shields.io/badge/Protocol-MTProto%202.0-2CA5E0.svg?style=flat-square&logo=telegram)](https://core.telegram.org/mtproto)
[![Architecture](https://img.shields.io/badge/Arch-ARM%20%7C%20x86-black.svg?style=flat-square)]()

---

Нативный автономный клиент Telegram для операционных систем семейств Windows CE и Windows Mobile, реализующий протокол MTProto 2.0 напрямую по TCP без использования промежуточных мостов, шлюзов и прокси-серверов.

---

## Ключевые цели

* **Автономность:** Прямое сетевое взаимодействие с серверами Telegram по протоколу MTProto 2.0 (TCP-порты 443 / 80 / 25).
* **Совместимость с широким спектром версий:**
  * Pocket PC 2000 / 2002 / 2003 / 2003 SE
  * Windows Mobile 5.0 / 6.0 / 6.1 / 6.5 / 6.5.3
  * Windows CE 4.2 / 5.0 / 6.0 (навигаторы, терминалы, КПК)
  * Архитектуры процессоров: ARM (ARMv4T, ARMv5TE, XScale) и x86.
* **Минимальные системные требования:**
  * Реализация на чистом ANSI C (C89/C99).
  * Прямая работа с системными API (Win32 GDI, Winsock 1.1 / 2.0).
  * Потребление оперативной памяти: 2-5 МБ (при жестком системном лимите Windows CE в 32 МБ на процесс).

---

## Архитектурные уровни

```
+--------------------------------------------------------+
|                   GUI (Win32 GDI)                      |  Windows CE / Win32
+--------------------------------------------------------+
|                 Telegram Client API                    |
|      (auth.signIn, messages.getHistory, sendMsg)       |  Кроссплатформенный C
+--------------------------+-----------------------------+
|   TL-кодек (сериализатор)|   MTProto 2.0 (сессии/пакеты)|  Кроссплатформенный C
+--------------------------+-----------------------------+
|         Криптография (AES-IGE, RSA, DH, SHA-256)       |  Кроссплатформенный C
+--------------------------------------------------------+
|               Сетевой транспорт (Winsock)              |  WinCE / Win32 / POSIX
+--------------------------------------------------------+
```

---

## Структура репозитория

| Директория | Описание |
| :--- | :--- |
| `include/cegram/` | Заголовочные файлы ядра (типы, криптография, сетевой транспорт, структуры MTProto). |
| `src/core/` | Реализация ядра: сетевой транспорт, криптографические алгоритмы, протокол MTProto 2.0. |
| `src/platform/cli/` | Консольный клиент для отладки протокола и криптографии на ПК. |
| `src/platform/wince/` | Нативный графический интерфейс для устройств под управлением Windows CE. |

---

## Текущий статус разработки

* [x] Сетевой транспорт Abridged MTProto по TCP.
* [x] Генерация криптографических нексов и расчет `message_id`.
* [x] Отправка `req_pq_multi` и прием `resPQ`.
* [x] Быстрое разложение PQ на множители P и Q методом Полларда.
* [x] Встроенные публичные RSA-ключи Telegram и сопоставление отпечатков.
* [x] Расчет SHA-1 и упаковка данных по схеме RSA-PAD.
* [x] Модульное возведение в степень для RSA-2048 через встроенный `mini-gmp`.
* [x] Отправка `req_DH_params` и успешное получение `server_DH_params_ok`.
* [x] Симметричное шифрование AES-256-IGE.
* [x] Завершение создания ключа авторизации (`set_client_DH_params` -> `dh_gen_ok`).
* [x] Шифрование пользовательских сессий MTProto 2.0 (AES-256-IGE + SHA-256 msg_key).
* [x] Обработка служебных сообщений MTProto (`new_session_created`, `bad_server_salt`, `msg_container`, `rpc_result`).
* [x] Сохранение и загрузка сессии (`session.dat`) без повторения рукопожатия.
* [x] Автоматическая инициализация сессии (`invokeWithLayer` Layer 184 + `initConnection`).
* [x] TL-сериализатор и парсер базовых типов Type Language.
* [x] Вызовы API методов: `help.getNearestDc`, `auth.sendCode`, `auth.signIn`.
* [x] Автоматическая миграция между дата-центрами (`PHONE_MIGRATE_X`).
* [x] Получение списка диалогов (`messages.getDialogs`).
* [x] Получение истории сообщений чата (`messages.getHistory`).
* [x] Отправка текстовых сообщений (`messages.sendMessage`).
* [x] Графический интерфейс Win32 GDI для Windows CE / Win32 (`src/platform/wince/gui_main.c`).
* [ ] Авторизация пользователя по облачному паролю (2FA SRP-6A).

---

## Сборка и тестирование

Для компиляции полного набора бинарных файлов (CLI и GUI) выполните:

```cmd
build.bat
```

В результате сборки создаются два исполняемых файла:
* `bin\cegram_cli.exe` - консольный интерфейс для полной диагностики протокола.
* `bin\cegram_gui.exe` - графическое приложение с адаптивным интерфейсом под Windows CE и Win32.

### Команды CLI-клиента:

```cmd
bin\cegram_cli.exe sendcode <номер_телефона> <api_id> <api_hash>
bin\cegram_cli.exe login <номер_телефона> <api_id> <api_hash>
bin\cegram_cli.exe dialogs [лимит]
bin\cegram_cli.exe history <тип_пира: 1=Self, 2=User, 3=Chat, 4=Channel> <peer_id> <access_hash_hex> [лимит]
bin\cegram_cli.exe send <тип_пира: 1=Self, 2=User, 3=Chat, 4=Channel> <peer_id> <access_hash_hex> <текст_сообщения>
```

---

## Сборка для Windows CE и запуск в эмуляторе

### 1. Кросс-компиляция (ARM / x86 CEPC)

Для сборки нативных исполняемых файлов под архитектуры процессоров ARM (Pocket PC / Windows Mobile) и x86 (CEPC) выполните:

```cmd
build_wince.bat
```

В результате сборки формируются бинарные файлы с импортом исключительно `COREDLL.dll` и `WS2.dll` (подсистема Windows CE GUI, машина `0x1C0` для ARM и `0x14C` для x86):
* `bin\cegram_gui_arm.exe` - графический клиент для Pocket PC 2003 / Windows Mobile (ARM).
* `bin\cegram_cli_arm.exe` - консольный клиент для Windows CE (ARM).
* `bin\cegram_gui_x86ce.exe` - графический клиент для Windows CE (x86 CEPC).
* `bin\cegram_cli_x86ce.exe` - консольный клиент для Windows CE (x86 CEPC).

### 2. Запуск в Microsoft Device Emulator

Для запуска автономного эмулятора Pocket PC 2003 Second Edition:

```cmd
run_emulator.bat
```

Папка `bin\` автоматически монтируется в операционной системе Windows CE как `\Storage Card`.

### 3. Инструкция по запуску внутри эмулятора

1. Запустите эмулятор с помощью скрипта `run_emulator.bat`.
2. После загрузки рабочего стола Pocket PC откройте меню **Start** -> **Programs** -> **File Explorer**.
3. В верхней строке выбора папки перейдите в **Storage Card**.
4. Запустите `cegram_gui_arm.exe`.
5. В открывшемся окне введите номер телефона, `API ID` и `API Hash`, нажмите **Send Code**, введите полученный код и выполните вход.
6. Для быстрого тестирования с уже созданной сессией скопируйте `session.dat` в директорию `bin\`, после чего приложение сразу загрузит список чатов.
